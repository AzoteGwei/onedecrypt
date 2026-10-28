"""Decrypt the B5 keyset graph, vault keys, and item payloads."""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import (
    DecryptionError,
    MukParams,
    derive_muk,
    jwe_decrypt,
    jwe_decrypt_json,
    symmetric_key_from_jwk,
)
from .database import Account, Item, Keyset, Progress, Vault
from .jwk import decrypt_jwe_with_rsa, rsa_private_key_from_jwk


@dataclass
class ResolvedKeyset:
    keyset: Keyset
    sym_key: bytes
    rsa_key: object


def _noop(_: str) -> None:
    pass


def resolve_keysets(
    keysets: list[Keyset],
    secret_key: str,
    password: str,
    email: str,
    progress: Progress = _noop,
) -> dict[str, ResolvedKeyset]:
    """Decrypt the account's keyset graph.

    Root keysets are encrypted by the MUK (``encryptedBy: "mp"``).  Child
    keysets are encrypted by a parent keyset's RSA public key.  Shared vaults
    may sit behind a chain of such keysets.
    """
    resolved: dict[str, ResolvedKeyset] = {}
    last_root_error: DecryptionError | None = None

    for keyset in keysets:
        if not keyset.is_root or keyset.enc_sym_key is None or keyset.enc_pri_key is None:
            continue
        try:
            params = MukParams.from_jwe(keyset.enc_sym_key)
            progress(
                f"keyset {keyset.uuid}: deriving MUK ({params.alg}, {params.iterations} iterations)"
            )
            muk = derive_muk(secret_key, password, email, params)
            sym_key = symmetric_key_from_jwk(jwe_decrypt(muk, keyset.enc_sym_key))
            rsa_key = rsa_private_key_from_jwk(jwe_decrypt(sym_key, keyset.enc_pri_key))
        except DecryptionError as exc:
            last_root_error = exc
            progress(f"keyset {keyset.uuid}: root unlock failed: {exc}")
            continue
        resolved[keyset.uuid] = ResolvedKeyset(keyset, sym_key, rsa_key)
        progress(f"keyset {keyset.uuid}: unlocked root key")

    changed = True
    while changed:
        changed = False
        for keyset in keysets:
            if keyset.uuid in resolved or keyset.enc_sym_key is None:
                continue
            parent = resolved.get(keyset.encrypted_by)
            if parent is None:
                continue
            try:
                enc_sym = keyset.enc_sym_key
                if enc_sym.get("enc", "").startswith("RSA-OAEP"):
                    payload = decrypt_jwe_with_rsa(parent.rsa_key, enc_sym)
                    sym_key = symmetric_key_from_jwk(payload)
                elif enc_sym.get("enc") == "A256GCM":
                    sym_key = symmetric_key_from_jwk(jwe_decrypt(parent.sym_key, enc_sym))
                else:
                    continue
                if keyset.enc_pri_key:
                    rsa_key = rsa_private_key_from_jwk(jwe_decrypt(sym_key, keyset.enc_pri_key))
                else:
                    rsa_key = parent.rsa_key
            except DecryptionError as exc:
                progress(f"keyset {keyset.uuid}: unlock failed: {exc}")
                continue
            resolved[keyset.uuid] = ResolvedKeyset(keyset, sym_key, rsa_key)
            progress(f"keyset {keyset.uuid}: unlocked from {keyset.encrypted_by}")
            changed = True

    if not resolved:
        detail = f" ({last_root_error})" if last_root_error else ""
        raise DecryptionError(
            "no root keyset could be unlocked; the Secret Key, password or account "
            f"selection is wrong{detail}"
        )
    return resolved


def _decrypt_vault_key(
    vault: Vault,
    resolved: dict[str, ResolvedKeyset],
    progress: Progress = _noop,
) -> bytes:
    jwe = vault.data.get("enc_vault_key")
    if not isinstance(jwe, dict):
        raise DecryptionError(f"vault {vault.uuid} has no enc_vault_key")
    kid = jwe.get("kid")
    alg = jwe.get("enc") or ""
    candidates = []
    if kid and kid in resolved:
        candidates.append(resolved[kid])
    candidates.extend(value for key, value in resolved.items() if key != kid)

    last_error: Exception | None = None
    for candidate in candidates:
        try:
            if alg.startswith("RSA-OAEP"):
                payload = decrypt_jwe_with_rsa(candidate.rsa_key, jwe)
                key = symmetric_key_from_jwk(payload)
            elif alg == "A256GCM":
                key = symmetric_key_from_jwk(jwe_decrypt(candidate.sym_key, jwe))
            else:
                raise DecryptionError(f"unsupported vault key algorithm {alg!r}")
            progress(f"vault {vault.uuid}: unlocked vault key via keyset {candidate.keyset.uuid}")
            return key
        except DecryptionError as exc:
            last_error = exc
    raise DecryptionError(f"could not decrypt vault key for {vault.uuid}: {last_error}")


def _decrypt_item_field(
    item: Item,
    field_name: str,
    vault_keys: list[bytes],
    progress: Progress = _noop,
) -> dict | None:
    jwe = item.data.get(field_name)
    if not isinstance(jwe, dict):
        return None
    if jwe.get("cty") != "b5+jwk+json" and "data" not in jwe:
        return jwe
    kid = jwe.get("kid")
    last_error: Exception | None = None
    for key in vault_keys:
        try:
            return jwe_decrypt_json(key, jwe)
        except DecryptionError as exc:
            last_error = exc
    raise DecryptionError(
        f"could not decrypt {field_name} of item {item.uuid} (kid={kid}): {last_error}"
    )


def decrypt_account(
    account: Account,
    secret_key: str,
    password: str,
    progress: Progress = _noop,
    include_items: bool = True,
) -> Account:
    """Decrypt an account in place and return it."""
    resolved = resolve_keysets(account.keysets, secret_key, password, account.email, progress)
    progress(f"account {account.uuid}: {len(resolved)} keyset(s) unlocked")

    for vault in account.vaults:
        try:
            vault.key = _decrypt_vault_key(vault, resolved, progress)
        except DecryptionError as exc:
            account.failed_vaults.append((vault.uuid, str(exc)))
            progress(f"vault {vault.uuid}: {exc}")
            continue
        attrs_jwe = vault.data.get("enc_attrs")
        if isinstance(attrs_jwe, dict):
            try:
                vault.attrs = jwe_decrypt_json(vault.key, attrs_jwe)
            except DecryptionError as exc:
                progress(f"vault {vault.uuid}: could not decrypt attrs: {exc}")
                vault.attrs = {}

    if not include_items:
        return account

    for vault in account.vaults:
        if vault.key is None:
            continue
        count = 0
        for item in vault.items:
            item_keys = [vault.key]
            # Newer B5 items may wrap a per-item symmetric key with the vault
            # key.  The 1Password 8.11 database used here stores item data
            # directly under the vault key, but accepting the extra layer
            # costs nothing and keeps the tool useful for newer databases.
            for field in ("enc_item_key", "encItemKey", "item_key", "itemKey"):
                wrapped = item.data.get(field)
                if not isinstance(wrapped, dict):
                    continue
                try:
                    item_keys.insert(0, symmetric_key_from_jwk(jwe_decrypt(vault.key, wrapped)))
                except DecryptionError:
                    continue
            try:
                item.details = _decrypt_item_field(item, "details", item_keys, progress)
                item.overview = _decrypt_item_field(item, "overview", item_keys, progress)
            except DecryptionError as exc:
                # Keep going: a single unreadable item must not block the
                # rescue of the rest of the vault.
                account.failed_items.append((item.uuid, str(exc)))
                progress(f"item {item.uuid}: {exc}")
                continue
            count += 1
        if count:
            progress(f"vault {vault.uuid}: decrypted {count} item(s)")
    return account
