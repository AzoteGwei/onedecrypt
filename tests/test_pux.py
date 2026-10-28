from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from helpers import synthetic_account, sym_jwk
from onedecrypt.crypto import b64u
from onedecrypt.database import Account, Item, Vault
from onedecrypt.decrypt import decrypt_account
from onedecrypt.pux import build_export_data, item_state, write_1pux


def test_item_state_mapping():
    assert item_state(0) == "active"
    assert item_state(1) == "archived"
    assert item_state(2) == "deleted"


def test_1pux_export_shape(tmp_path: Path):
    account = synthetic_account()
    decrypt_account(
        account,
        "A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB",
        "update-clown-squid-bedpost",
    )
    data, files = build_export_data(account)
    item = data["accounts"][0]["vaults"][0]["items"][0]
    assert item["categoryUuid"] == "001"
    assert item["state"] == "active"
    assert item["favIndex"] == 1
    assert item["details"]["loginFields"][1]["value"] == "secret"
    assert item["overview"]["title"] == "Example"

    path, item_count, file_count = write_1pux(tmp_path / "out.1pux", account)
    assert item_count == 1
    assert file_count == 0
    with zipfile.ZipFile(path) as zf:
        assert set(zf.namelist()) == {"export.attributes", "export.data"}
        attributes = json.loads(zf.read("export.attributes"))
        assert attributes["version"] == 3
        exported = json.loads(zf.read("export.data"))
        assert exported["accounts"][0]["attrs"]["uuid"] == "ACCOUNT"
