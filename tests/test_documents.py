from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from helpers import sym_jwk
from onedecrypt.crypto import b64u
from onedecrypt.documents import extract_document


def test_document_decryption(tmp_path: Path):
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"document body"
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    files_dir = tmp_path / "files"
    (files_dir / "ACCOUNT").mkdir(parents=True)
    (files_dir / "ACCOUNT" / "docid").write_bytes(ciphertext)

    details = {
        "documentAttributes": {
            "documentId": "docid",
            "fileName": "note.txt",
            "nonce": b64u(nonce),
            "integrityHash": b64u(hashlib.sha256(plaintext).digest()),
            "encryptionKey": sym_jwk(key, "file"),
            "encryptedSize": len(ciphertext),
            "unencryptedSize": len(plaintext),
        }
    }
    file_name, content = extract_document(details, "ACCOUNT", files_dir)
    assert file_name == "note.txt"
    assert content == plaintext
