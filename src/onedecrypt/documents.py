"""Decrypt and normalize locally cached 1Password document blobs."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterator

from .crypto import DecryptionError, aes_gcm_decrypt, b64d, symmetric_key_from_jwk


def safe_file_name(name: str) -> str:
    return Path(name).name.replace("\x00", "_")


def _is_file_reference(value: object) -> bool:
    return isinstance(value, dict) and bool(value.get("documentId") or value.get("document_id"))


def iter_file_references(details: dict) -> Iterator[dict]:
    """Yield every file reference in a decrypted item details object.

    1PUX has two file locations: the top-level ``documentAttributes`` of a
    Document item, and ``sections[].fields[].value.file`` for attachments.
    """
    if not isinstance(details, dict):
        return
    document_attributes = details.get("documentAttributes")
    if _is_file_reference(document_attributes):
        yield document_attributes
    sections = details.get("sections")
    if not isinstance(sections, list):
        return
    for section in sections:
        if not isinstance(section, dict):
            continue
        fields = section.get("fields")
        if not isinstance(fields, list):
            continue
        for field in fields:
            if not isinstance(field, dict):
                continue
            value = field.get("value", field.get("v"))
            if not isinstance(value, dict):
                continue
            file_value = value.get("file")
            if _is_file_reference(file_value):
                yield file_value
            elif _is_file_reference(value):
                yield value


def clean_file_reference(reference: dict, decrypted_size: int | None = None) -> dict:
    document_id = reference.get("documentId") or reference.get("document_id")
    file_name = reference.get("fileName") or reference.get("file_name") or document_id
    result = {
        "fileName": safe_file_name(str(file_name)),
        "documentId": str(document_id),
    }
    size = decrypted_size
    if size is None:
        size = reference.get("decryptedSize")
    if size is None:
        size = reference.get("unencryptedSize")
    if isinstance(size, bool):
        size = int(size)
    if isinstance(size, int):
        result["decryptedSize"] = size
    return result


def _document_path(
    document_id: str, account_uuid: str, files_dir: Path
) -> Path | None:
    candidates = [files_dir / account_uuid / document_id]
    if files_dir.exists():
        for child in files_dir.iterdir():
            if child.is_dir() and child != files_dir / account_uuid:
                candidates.append(child / document_id)
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def extract_file_reference(
    reference: dict,
    account_uuid: str,
    files_dir: Path | None,
    fallback_key: bytes | None = None,
) -> tuple[str, bytes] | None:
    """Return ``(fileName, plaintext)`` for one file reference."""
    if not _is_file_reference(reference) or files_dir is None:
        return None
    document_id = str(reference.get("documentId") or reference.get("document_id"))
    file_name = safe_file_name(
        str(reference.get("fileName") or reference.get("file_name") or document_id)
    )
    path = _document_path(document_id, account_uuid, files_dir)
    if path is None:
        raise FileNotFoundError(f"document {document_id} not found under {files_dir}")

    ciphertext = path.read_bytes()
    encryption_key = reference.get("encryptionKey")
    nonce = reference.get("nonce")
    integrity = reference.get("integrityHash")

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
        # it in the reference.
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
            return file_name, ciphertext
        except ValueError:
            pass
    raise DecryptionError(
        f"document {document_id}: no key or integrity hash; refusing to export "
        "unverified file bytes"
    )


def extract_document(
    details: dict,
    account_uuid: str,
    files_dir: Path | None,
    fallback_key: bytes | None = None,
) -> tuple[str, bytes] | None:
    """Backward-compatible helper for a top-level document item."""
    attrs = details.get("documentAttributes")
    if not isinstance(attrs, dict):
        return None
    return extract_file_reference(attrs, account_uuid, files_dir, fallback_key)
