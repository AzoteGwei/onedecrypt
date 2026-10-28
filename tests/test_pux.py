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
from onedecrypt.pux_schema import (
    ITEM_KEYS,
    PROFILE_EXPORTER,
    PROFILE_FULL,
    PROFILE_IMPORTER,
    PROFILE_OFFICIAL,
    SchemaError,
    validate_export_data,
)


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
        assert set(attributes) == {"version", "description", "timestamp"}
        assert attributes["version"] == 3
        exported = json.loads(zf.read("export.data"))
        assert exported["accounts"][0]["attrs"]["uuid"] == "ACCOUNT"


def test_item_wrapper_matches_official_v3():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    data, _ = build_export_data(account)
    item = data["accounts"][0]["vaults"][0]["items"][0]
    assert set(item) == ITEM_KEYS
    assert "trashed" not in item
    assert "changerUuid" not in item


def test_short_section_fields_are_converted():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.details = {
        "notesPlain": "note",
        "sections": [
            {
                "title": "",
                "name": "add more",
                "fields": [
                    {
                        "t": "PIN",
                        "n": "pin1",
                        "k": "concealed",
                        "v": "1234",
                        "a": {"multiline": "no"},
                        "inputTraits": {"autocorrection": "no", "autocapitalization": "none"},
                    }
                ],
            }
        ],
        "htmlForm": {
            "htmlMethod": "POST",
            "htmlAction": "/login",
            "htmlID": "form1",
            "htmlName": "login",
        },
    }
    item.overview = {
        "title": "Example",
        "url": "https://example.com",
        "urls": [{"label": "", "url": "https://example.com", "mode": "anywhereOnWebsite"}],
        "tags": ["work"],
        "ainfo": "user@example.com",
        "icons": {"1": {"type": "default"}},
    }
    data, _ = build_export_data(account)
    details = data["accounts"][0]["vaults"][0]["items"][0]["details"]
    field = details["sections"][0]["fields"][0]
    assert field == {
        "title": "PIN",
        "id": "pin1",
        "value": {"concealed": "1234"},
        "multiline": False,
        "inputTraits": {"correction": "no", "capitalization": "none"},
    }
    assert details["htmlForm"] == {
        "htmlMethod": "POST",
        "htmlAction": "/login",
        "htmlID": "form1",
        "htmlName": "login",
    }
    overview = data["accounts"][0]["vaults"][0]["items"][0]["overview"]
    assert overview["subtitle"] == "user@example.com"
    assert overview["urls"] == [
        {"label": "", "url": "https://example.com", "mode": "anywhereOnWebsite"}
    ]
    assert overview["icons"] == {"1": {"type": "default"}}
    assert "ainfo" not in overview


def test_login_field_type_is_not_restricted_to_a_short_enum():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.details = {
        "loginFields": [
            {"value": "u", "name": "username", "fieldType": "D", "designation": "username"}
        ]
    }
    data, _ = build_export_data(account)
    field = data["accounts"][0]["vaults"][0]["items"][0]["details"]["loginFields"][0]
    assert field["fieldType"] == "D"


def test_passkeys_follow_profile_capabilities():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.details = {
        "loginFields": [{"value": "u", "name": "username", "fieldType": "T", "designation": "username"}],
        "passkey": {
            "type": "webauthn",
            "createdAt": 1700000000,
            "privateKey": "not-a-real-key",
            "userHandle": "dXNlcg",
        },
    }
    for profile in (PROFILE_OFFICIAL, PROFILE_EXPORTER):
        data, _ = build_export_data(account, profile=profile)
        details = data["accounts"][0]["vaults"][0]["items"][0]["details"]
        assert "passkey" not in details
    for profile in (PROFILE_IMPORTER, PROFILE_FULL):
        data, _ = build_export_data(account, profile=profile)
        details = data["accounts"][0]["vaults"][0]["items"][0]["details"]
        assert details["passkey"]["type"] == "webauthn"


def test_full_profile_keeps_extra_metadata():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.data["changer_uuid"] = "USER"
    item.data["state"] = 1
    item.overview = {"title": "Example", "scope": "private"}
    item.details = {"sections": [{"name": "s", "title": "", "fields": []}]}
    data, _ = build_export_data(account, profile=PROFILE_FULL)
    full_item = data["accounts"][0]["vaults"][0]["items"][0]
    assert full_item["state"] == "archived"
    assert full_item["stateRaw"] == 1
    assert full_item["trashed"] == "N"
    assert full_item["changerUuid"] == "USER"
    assert full_item["scope"] == "private"
    assert full_item["details"] == item.details
    validate_export_data(data, PROFILE_FULL)
    with_extra = json.loads(json.dumps(data))
    try:
        validate_export_data(with_extra, PROFILE_OFFICIAL)
    except SchemaError:
        pass
    else:
        raise AssertionError("official profile accepted full-profile extras")


def test_schema_rejects_non_official_fields():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    data, _ = build_export_data(account)
    data["accounts"][0]["vaults"][0]["items"][0]["trashed"] = "N"
    try:
        validate_export_data(data, PROFILE_OFFICIAL)
    except SchemaError:
        pass
    else:
        raise AssertionError("validator accepted a non-official item field")
