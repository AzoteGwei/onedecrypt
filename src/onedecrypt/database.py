"""Read-only access to the 1Password 8 ``1password.sqlite`` database.

Schema (version 61, 1Password 8.11/8.12):

  accounts(account_uuid TEXT PRIMARY KEY, data BLOB)
  vaults(account_uuid, vault_uuid, data BLOB)
  items(account_uuid, vault_uuid, item_uuid, data BLOB, ...)
  objects_associated(type, account_uuid, key_name, data, vault_uuid, item_uuid)

The JSON rows use snake_case at the outer layer.  The encrypted payloads
inside ``data`` are B5 JWE-B objects (``cty: b5+jwk+json``).  Keysets are
stored in ``objects_associated`` with ``type = 36``; the row key is the
keyset UUID.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .crypto import DecryptionError

KEYSET_OBJECT_TYPE = 36

Progress = Callable[[str], None]


def _load_json(blob: bytes | str) -> dict:
    if isinstance(blob, bytes):
        blob = blob.decode("utf-8")
    value = json.loads(blob)
    if not isinstance(value, dict):
        raise DecryptionError("expected a JSON object")
    return value


@dataclass
class Keyset:
    uuid: str
    data: dict

    @property
    def encrypted_by(self) -> str:
        return self.data.get("encryptedBy") or ""

    @property
    def enc_sym_key(self) -> dict | None:
        value = self.data.get("encSymKey")
        return value if isinstance(value, dict) else None

    @property
    def enc_pri_key(self) -> dict | None:
        value = self.data.get("encPriKey")
        return value if isinstance(value, dict) else None

    @property
    def is_root(self) -> bool:
        return self.encrypted_by == "mp" or (
            self.enc_sym_key is not None and self.enc_sym_key.get("kid") == "mp"
        )


@dataclass
class Item:
    uuid: str
    vault_uuid: str
    data: dict
    details: dict | None = None
    overview: dict | None = None


@dataclass
class Vault:
    uuid: str
    data: dict
    attrs: dict | None = None
    key: bytes | None = None
    items: list[Item] = field(default_factory=list)

    @property
    def type(self) -> str:
        return self.data.get("vault_type") or (self.attrs or {}).get("type") or ""


@dataclass
class Account:
    uuid: str
    data: dict
    keysets: list[Keyset] = field(default_factory=list)
    vaults: list[Vault] = field(default_factory=list)
    failed_items: list[tuple[str, str]] = field(default_factory=list)
    failed_vaults: list[tuple[str, str]] = field(default_factory=list)

    @property
    def email(self) -> str:
        return self.data.get("user_email") or ""

    @property
    def name(self) -> str:
        return self.data.get("user_name") or ""

    @property
    def team_name(self) -> str:
        return self.data.get("team_name") or ""


class LocalDatabase:
    """Read-only access to a 1Password local database.

    The desktop app keeps the database in WAL mode.  Opening it read-only
    while the app holds the write lock can fail, so we copy the main file and
    its ``-wal``/``-shm`` sidecars to a private temporary directory.  The
    original database is never modified.
    """

    def __init__(self, path: str | Path):
        self.source_path = Path(path).expanduser().resolve()
        if not self.source_path.exists():
            raise FileNotFoundError(f"database not found: {self.source_path}")
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.path = self._prepare_copy()
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row

    def _prepare_copy(self) -> Path:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="onedecrypt-")
        target = Path(self._tmpdir.name) / self.source_path.name
        shutil.copy2(self.source_path, target)
        for suffix in ("-wal", "-shm"):
            sidecar = self.source_path.with_name(self.source_path.name + suffix)
            if sidecar.exists():
                shutil.copy2(sidecar, target.with_name(target.name + suffix))
        return target

    def close(self) -> None:
        try:
            self.conn.close()
        finally:
            if self._tmpdir is not None:
                self._tmpdir.cleanup()
                self._tmpdir = None

    def __enter__(self) -> "LocalDatabase":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def accounts(self) -> list[Account]:
        result = []
        for row in self.conn.execute("SELECT account_uuid, data FROM accounts ORDER BY account_uuid"):
            account_uuid = row["account_uuid"]
            result.append(
                Account(
                    uuid=account_uuid,
                    data=_load_json(row["data"]),
                    keysets=self.keysets(account_uuid),
                    vaults=self.vaults(account_uuid),
                )
            )
        return result

    def keysets(self, account_uuid: str) -> list[Keyset]:
        keysets = []
        for row in self.conn.execute(
            "SELECT key_name, data FROM objects_associated WHERE type = ? AND account_uuid = ?",
            (KEYSET_OBJECT_TYPE, account_uuid),
        ):
            try:
                keysets.append(Keyset(uuid=row["key_name"], data=_load_json(row["data"])))
            except (json.JSONDecodeError, UnicodeDecodeError, DecryptionError):
                continue
        return keysets

    def vaults(self, account_uuid: str) -> list[Vault]:
        vaults = []
        for row in self.conn.execute(
            "SELECT vault_uuid, data FROM vaults WHERE account_uuid = ? ORDER BY vault_uuid",
            (account_uuid,),
        ):
            vaults.append(Vault(uuid=row["vault_uuid"], data=_load_json(row["data"])))
        return vaults

    def items(self, account_uuid: str, vault_uuid: str) -> Iterable[Item]:
        for row in self.conn.execute(
            "SELECT item_uuid, data FROM items WHERE account_uuid = ? AND vault_uuid = ? "
            "ORDER BY item_uuid",
            (account_uuid, vault_uuid),
        ):
            yield Item(uuid=row["item_uuid"], vault_uuid=vault_uuid, data=_load_json(row["data"]))


def load_items(account: Account, db: LocalDatabase) -> None:
    for vault in account.vaults:
        if not vault.items:
            vault.items = list(db.items(account.uuid, vault.uuid))


def find_account(accounts: list[Account], query: str) -> Account:
    q = query.strip().lower()
    exact = [a for a in accounts if q in (a.uuid.lower(), a.email.lower(), a.name.lower())]
    if len(exact) == 1:
        return exact[0]
    partial = [
        a
        for a in accounts
        if q in a.uuid.lower() or q in a.email.lower() or q in a.name.lower() or q in a.team_name.lower()
    ]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise SystemExit(f"no account matches {query!r}")
    names = ", ".join(f"{a.email or a.name} ({a.uuid})" for a in partial)
    raise SystemExit(f"account {query!r} is ambiguous; matches: {names}")
