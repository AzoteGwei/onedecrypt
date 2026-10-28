"""Decrypt locally cached 1Password document blobs."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .crypto import DecryptionError, aes_gcm_decrypt, b64d, symmetric_key_from_jwk


def safe_file_name(name: str) -> str:
    return Path(name).name.replace("\x00", "_")


def extract_document(
    details: dict,
    account_uuid: str,
    files_dir: Path | None,
    fallback_key: bytes | None = None,
) -> tuple[str, bytes] | None:
    """Return ``(fileName, plaintext)`` for a document item, if present.

    ``documentAttributes`` carries a per-file symmetric JWK, the nonce and an
    integrity hash; the encrypted blob is stored under
    ``files/<account_uuid>/<documentId>``.
    """
    attrs = details.get("documentAttributes")
    if not isinstance(attrs, dict):
        return None
    document_id = attrs.get("documentId") or attrs.get("document_id")
    if not document_id or files_dir is None:
        return None
    file_name = safe_file_name(attrs.get("fileName") or attrs.get("file_name") or document_id)
    candidates = [files_dir / account_uuid / document_id]
    if files_dir.exists():
        for child in files_dir.iterdir():
            if child.is_dir() and child != files_dir / account_uuid:
                candidates.append(child / document_id)
    path = next((c for c in candidates if c.is_file()), None)
    if path is None:
        raise FileNotFoundError(f"document {document_id} not found under {files_dir}")

    ciphertext = path.read_bytes()
    encryption_key = attrs.get("encryptionKey")
    nonce = attrs.get("nonce")
    integrity = attrs.get("integrityHash")

    key = symmetric_key_from_jwk(encryption_key) if encryption_key else fallback_key
    if key:
        if nonce:
            try:
                # AES-GCM has already authenticated the plaintext.  The
                # additional integrity hash is a legacy check; some caches
                # store it in a different base64 dialect, so a mismatch is not
                # fatal.
                return file_name, aes_gcm_decrypt(key, b64d(nonce), ciphertext)
            except (DecryptionError, ValueError):
                pass
        # A few caches prefix the nonce to the ciphertext instead of keeping
        # it in documentAttributes.
        for nonce_size in (12, 16):
            if len(ciphertext) > nonce_size + 16:
                try:
                    return file_name, aes_gcm_decrypt(
                        key, ciphertext[:nonce_size], ciphertext[nonce_size:]
                    )
                except DecryptionError:
                    continue
        raise DecryptionError(f"document {document_id}: could not decrypt file blob")

    # Offline caches written by some versions are already decrypted.  Only
    # accept that interpretation when the integrity hash agrees, otherwise we
    # would silently export ciphertext as a document.
    if integrity:
        try:
            expected = b64d(integrity)
            if hashlib.sha256(ciphertext).digest() != expected:
                raise DecryptionError(
                    f"document {document_id}: ciphertext is not a recognised "
                    "encrypted or plaintext document"
                )
        except ValueError:
            pass
    return file_name, ciphertext
