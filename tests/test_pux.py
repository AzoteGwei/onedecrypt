from __future__ import annotations

import hashlib
import json
import os
import warnings
import zipfile
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from helpers import synthetic_account, sym_jwk
from onedecrypt.crypto import b64u
from onedecrypt.database import Account, Item, Vault
from onedecrypt.decrypt import decrypt_account
from onedecrypt.pux import build_export_data, item_state, shape_report, write_1pux
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
            "htmlId": "form1",
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
        "guarded": False,
        "multiline": False,
        "dontGenerate": False,
        "inputTraits": {
            "keyboard": "default",
            "correction": "no",
            "capitalization": "none",
        },
    }
    assert details["htmlForm"] == {
        "htmlMethod": "POST",
        "htmlAction": "/login",
        "htmlId": "form1",
        "htmlName": "login",
    }
    overview = data["accounts"][0]["vaults"][0]["items"][0]["overview"]
    assert overview["subtitle"] == "user@example.com"
    assert overview["url"] == "https://example.com"
    assert "pgrng" not in overview
    assert overview["icons"] is None
    assert overview["watchtowerExclusions"] is None
    assert overview["urls"] == [
        {"label": "", "url": "https://example.com", "mode": "default"}
    ]
    assert "ainfo" not in overview


def test_overview_urls_accept_legacy_alias_and_entry_forms():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.overview = {
        "title": "Example",
        "url": "",
        "URLs": [
            {"label": "website", "url": "https://one.example", "mode": "default"},
            ["website", "https://two.example"],
            ["website", "https://three.example", "never"],
            "https://four.example",
        ],
    }
    data, _ = build_export_data(account)
    overview = data["accounts"][0]["vaults"][0]["items"][0]["overview"]
    assert "URLs" not in overview
    assert overview["url"] == "https://one.example"
    assert overview["urls"] == [
        {"label": "website", "url": "https://one.example", "mode": "default"},
        {"label": "website", "url": "https://two.example", "mode": "default"},
        {"label": "website", "url": "https://three.example", "mode": "never"},
        {"label": "", "url": "https://four.example", "mode": "default"},
    ]


def test_overview_urls_accept_short_keys_and_numeric_modes():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.overview = {
        "title": "Example",
        "url": "https://primary.example",
        "urls": [
            {"l": "website", "u": "https://one.example", "m": 0},
            {"l": "website", "u": "https://two.example", "m": 1},
            {"l": "website", "u": "https://three.example", "m": 2},
        ],
    }
    data, _ = build_export_data(account)
    overview = data["accounts"][0]["vaults"][0]["items"][0]["overview"]
    assert overview["url"] == "https://primary.example"
    assert overview["urls"] == [
        {"label": "website", "url": "https://one.example", "mode": "default"},
        {"label": "website", "url": "https://two.example", "mode": "host"},
        {"label": "website", "url": "https://three.example", "mode": "never"},
    ]


def test_overview_urls_drop_malformed_entries():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.overview = {
        "title": "Example",
        "url": "https://one.example",
        "urls": [
            {"label": "website", "url": "https://one.example"},
            ["bad", {"nested": 1}],
            {"label": "bad", "url": {"nested": 1}},
            {"label": {"nested": 1}, "url": "https://two.example"},
        ],
    }
    data, _ = build_export_data(account)
    overview = data["accounts"][0]["vaults"][0]["items"][0]["overview"]
    assert overview["urls"] == [
        {"label": "website", "url": "https://one.example", "mode": "default"},
        {"label": "", "url": "https://two.example", "mode": "default"},
    ]


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
    item.overview = {"title": "Example", "passkey": {"type": "webauthn"}}
    # The importer's ItemDetails/ItemOverview visitors accept passkey fields
    # only through force_none, which discards the payload.  No importable
    # profile can transfer a passkey; only the raw full profile keeps the
    # local metadata for backup.
    for profile in (PROFILE_OFFICIAL, PROFILE_EXPORTER, PROFILE_IMPORTER):
        data, _ = build_export_data(account, profile=profile)
        item_data = data["accounts"][0]["vaults"][0]["items"][0]
        assert "passkey" not in item_data["details"]
        assert "passkey" not in item_data["overview"]
    data, _ = build_export_data(account, profile=PROFILE_FULL)
    item_data = data["accounts"][0]["vaults"][0]["items"][0]
    assert item_data["details"]["passkey"]["type"] == "webauthn"
    assert item_data["overview"]["passkey"]["type"] == "webauthn"
    validate_export_data(data, PROFILE_FULL)
    passkey_data, _ = build_export_data(
        account, profile=PROFILE_IMPORTER
    )
    passkey_item = passkey_data["accounts"][0]["vaults"][0]["items"][0]
    passkey_item["details"]["passkey"] = {"type": "webauthn"}
    for profile in (PROFILE_OFFICIAL, PROFILE_EXPORTER, PROFILE_IMPORTER):
        with pytest.raises(SchemaError, match="passkey"):
            validate_export_data(passkey_data, profile)
    passkey_item["details"].pop("passkey")
    passkey_item["overview"]["passkey"] = {"type": "webauthn"}
    for profile in (PROFILE_OFFICIAL, PROFILE_EXPORTER, PROFILE_IMPORTER):
        with pytest.raises(SchemaError, match="passkey"):
            validate_export_data(passkey_data, profile)


def test_scalar_ssh_private_key_becomes_ssh_key_value():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.data["category_uuid"] = "114"
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MFECAQEwBQYDK2VwBCIEIDIPmvzXim/Xt94YrEmBnNpcUKZm1mSDYpZoJmNEAzW6\n"
        "-----END PRIVATE KEY-----\n"
    )
    item.details = {
        "sections": [
            {
                "title": "",
                "fields": [
                    {"title": "private key", "id": "private_key", "v": pem},
                    {
                        "title": "private key alias",
                        "id": "private_key_alias",
                        "k": "private_key",
                        "v": pem,
                    },
                    {
                        "title": "private key object",
                        "id": "private_key_object",
                        "v": {"privateKey": pem},
                    },
                    {
                        "title": "private key flat metadata",
                        "id": "private_key_flat",
                        "v": {
                            "privateKey": pem,
                            "publicKey": "ssh-ed25519 AAAA",
                            "fingerprint": "SHA256:test",
                            "keyType": "ed25519",
                        },
                    },
                    {
                        "title": "SSH key material",
                        "id": "ssh_material",
                        "k": "concealed",
                        "v": pem,
                    },
                    {
                        "title": "SSH key material string",
                        "id": "ssh_material_string",
                        "k": "string",
                        "v": pem,
                    },
                    {
                        "title": "SSH note",
                        "id": "private_key_passphrase",
                        "k": "concealed",
                        "v": "hunter2",
                    },
                    {
                        "title": "SSH key wrapped",
                        "id": "ssh_key_wrapped",
                        "k": "string",
                        "v": {"concealed": pem},
                    },
                    {
                        "title": "SSH key with extra keys",
                        "id": "ssh_key_extra",
                        "k": "sshKey",
                        "v": {"sshKey": {"privateKey": pem}, "extra": 1},
                    },
                ],
            }
        ]
    }
    data, _ = build_export_data(account)
    fields = data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0][
        "fields"
    ]
    assert fields[0]["value"] == {"sshKey": {"privateKey": pem}}
    assert fields[1]["value"] == {"sshKey": {"privateKey": pem}}
    assert fields[2]["value"] == {"sshKey": {"privateKey": pem}}
    assert fields[3]["value"] == {
        "sshKey": {
            "privateKey": pem,
            "metadata": {
                "privateKey": pem,
                "publicKey": "ssh-ed25519 AAAA",
                "fingerprint": "SHA256:test",
                "keyType": "ed25519",
            },
        }
    }
    assert fields[4]["value"] == {"sshKey": {"privateKey": pem}}
    assert fields[5]["value"] == {"sshKey": {"privateKey": pem}}
    assert fields[6]["value"] == {"concealed": "hunter2"}
    assert fields[7]["value"] == {"sshKey": {"privateKey": pem}}
    assert fields[8]["value"] == {"sshKey": {"privateKey": pem}}
    validate_export_data(data, PROFILE_OFFICIAL)


def test_full_profile_keeps_extra_metadata():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.data["changer_uuid"] = "USER"
    item.data["state"] = 1
    account.vaults[0].data["vault_type"] = "G"
    item.overview = {"title": "Example", "scope": "private", "icons": {"1": {"type": "default"}}}
    item.details = {"sections": [{"name": "s", "title": "", "fields": []}]}
    official_data, _ = build_export_data(account, profile=PROFILE_OFFICIAL)
    assert official_data["accounts"][0]["vaults"][0]["attrs"]["type"] == "U"
    data, _ = build_export_data(account, profile=PROFILE_FULL)
    full_item = data["accounts"][0]["vaults"][0]["items"][0]
    assert full_item["state"] == "archived"
    assert full_item["stateRaw"] == 1
    assert full_item["trashed"] == "N"
    assert full_item["changerUuid"] == "USER"
    assert full_item["scope"] == "private"
    assert full_item["overview"]["icons"] == {"1": {"type": "default"}}
    assert data["accounts"][0]["vaults"][0]["attrs"]["type"] == "G"
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


def test_section_file_reference_is_cleaned_and_exported(tmp_path: Path):
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"attachment body"
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    files_dir = tmp_path / "files"
    (files_dir / "ACCOUNT").mkdir(parents=True)
    (files_dir / "ACCOUNT" / "doc1").write_bytes(ciphertext)

    account = synthetic_account()
    account.vaults[0].key = key
    item = account.vaults[0].items[0]
    item.details = {
        "sections": [
            {
                "name": "attachments",
                "title": "",
                "fields": [
                    {
                        "t": "Attachment",
                        "n": "f1",
                        "k": "file",
                        "v": {
                            "file": {
                                "fileName": "a.txt",
                                "documentId": "doc1",
                                "decryptedSize": len(plaintext),
                                "nonce": b64u(nonce),
                                "encryptionKey": sym_jwk(key, "file"),
                            }
                        },
                    }
                ],
            }
        ]
    }
    data, files = build_export_data(account, files_dir)
    assert files == {"files/doc1__a.txt": plaintext}
    field = data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"][0]
    assert field["value"] == {
        "file": {
            "fileName": "a.txt",
            "documentId": "doc1",
            "decryptedSize": len(plaintext),
        }
    }


def test_missing_document_item_keeps_item_without_file(tmp_path: Path):
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.data["category_uuid"] = "006"
    item.details = {
        "documentAttributes": {
            "fileName": "missing.pdf",
            "documentId": "missing",
            "decryptedSize": 10,
        }
    }
    item.overview = {"title": "Missing document"}
    data, files = build_export_data(account, tmp_path / "files")
    items = data["accounts"][0]["vaults"][0]["items"]
    assert len(items) == 1
    assert items[0]["overview"]["title"] == "Missing document"
    assert "documentAttributes" not in items[0]["details"]
    assert files == {}

    full, full_files = build_export_data(
        account, tmp_path / "files", profile=PROFILE_FULL
    )
    full_items = full["accounts"][0]["vaults"][0]["items"]
    assert len(full_items) == 1
    assert "documentAttributes" not in full_items[0]["details"]
    assert full_files == {}


def test_deleted_items_follow_the_official_exporter():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.data["state"] = 2

    official, _ = build_export_data(account, profile=PROFILE_OFFICIAL)
    assert official["accounts"][0]["vaults"][0]["items"] == []

    exporter, _ = build_export_data(account, profile=PROFILE_EXPORTER)
    assert exporter["accounts"][0]["vaults"][0]["items"] == []

    importer, _ = build_export_data(account, profile=PROFILE_IMPORTER)
    assert importer["accounts"][0]["vaults"][0]["items"][0]["state"] == "deleted"

    full, _ = build_export_data(account, profile=PROFILE_FULL)
    assert full["accounts"][0]["vaults"][0]["items"][0]["state"] == "deleted"


def test_section_scalar_value_is_tagged():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.details = {
        "sections": [
            {
                "title": "",
                "name": "s",
                "fields": [{"title": "Note", "id": "n1", "value": "plain text"}],
            }
        ]
    }
    data, _ = build_export_data(account, profile=PROFILE_OFFICIAL)
    field = data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"][0]
    assert field["value"] == {"string": "plain text"}


def test_overview_types_are_checked():
    from onedecrypt.pux_schema import _validate_overview

    with pytest.raises(SchemaError, match="ps"):
        _validate_overview(
            {
                "title": "Example",
                "subtitle": "",
                "url": "",
                "icons": None,
                "watchtowerExclusions": None,
                "ps": 100.5,
            },
            "overview",
        )


def test_no_files_suppresses_document_warnings():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.data["category_uuid"] = "006"
    item.details = {
        "documentAttributes": {
            "fileName": "missing.pdf",
            "documentId": "missing",
            "decryptedSize": 10,
        }
    }
    item.overview = {"title": "Missing document"}
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        data, files = build_export_data(account, files_dir=None)
    items = data["accounts"][0]["vaults"][0]["items"]
    assert len(items) == 1
    assert items[0]["overview"]["title"] == "Missing document"
    assert "documentAttributes" not in items[0]["details"]
    assert files == {}
    assert not [w for w in caught if "no locally available file" in str(w.message)]


def test_shape_report_omits_values():
    report = shape_report(
        {"password": "secret", "count": 3, "items": [{"enabled": True}]}
    )
    rendered = json.dumps(report)
    assert "secret" not in rendered
    assert report["keys"]["password"] == {"type": "string"}
    assert report["keys"]["count"] == {"type": "integer"}
    assert report["keys"]["items"]["items"] == [
        {"type": "object", "keys": {"enabled": {"type": "boolean"}}}
    ]


def test_date_and_month_year_values_are_typed_integers():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.details = {
        "sections": [
            {
                "title": "",
                "name": "s",
                "fields": [
                    {"title": "Date", "id": "d", "k": "date", "v": 20240131},
                    {"title": "Month", "id": "m", "k": "monthYear", "v": 202401},
                ],
            }
        ]
    }
    data, _ = build_export_data(account, profile=PROFILE_OFFICIAL)
    fields = data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"]
    assert fields[0]["value"] == {"date": 20240131}
    assert fields[1]["value"] == {"monthYear": 202401}


def test_input_traits_always_include_all_three_fields():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.details = {
        "sections": [
            {
                "title": "",
                "name": "s",
                "fields": [
                    {"title": "Empty", "id": "a"},
                    {"title": "One", "id": "b", "inputTraits": {"correction": "no"}},
                ],
            }
        ]
    }
    data, _ = build_export_data(account)
    fields = data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0][
        "fields"
    ]
    assert fields[0]["inputTraits"] == {
        "keyboard": "default",
        "correction": "default",
        "capitalization": "default",
    }
    assert fields[1]["inputTraits"] == {
        "keyboard": "default",
        "correction": "no",
        "capitalization": "default",
    }


def test_section_values_match_official_payload_shapes():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.details = {
        "sections": [
            {
                "title": "",
                "name": "s",
                "fields": [
                    {
                        "title": "Address",
                        "id": "a",
                        "k": "address",
                        "v": {
                            "streetAddress": "1 Main",
                            "city": "Springfield",
                            "territory": "CA",
                            "postalCode": "12345",
                            "country": "US",
                        },
                    },
                    {
                        "title": "SSH",
                        "id": "k",
                        "k": "sshKey",
                        "v": {
                            "privateKey": "priv",
                            "metadata": {
                                "publicKey": "pub",
                                "fingerprint": "fp",
                                "keyType": "rsa2048",
                            },
                        },
                    },
                    {
                        "title": "SSO",
                        "id": "s",
                        "k": "ssoLogin",
                        "v": {
                            "provider": "okta",
                            "item": {"itemUuid": "i", "vaultUuid": "v"},
                        },
                    },
                    {
                        "title": "Reference",
                        "id": "r",
                        "k": "reference",
                        "v": {"itemUuid": "i"},
                    },
                    {
                        "title": "Formatted",
                        "id": "f",
                        "k": "formattedText",
                        "v": {
                            "content": "hi",
                            "content_type": "text",
                            "content_format": "plaintext",
                            "format_version": 1,
                            "plain_text_display_value": "hi",
                            "html_display_value": "<p>hi</p>",
                        },
                    },
                    {
                        "title": "Managed",
                        "id": "m",
                        "k": "managedApplication",
                        "v": {
                            "applicationUuid": "app",
                            "loginInitiationUrl": "https://example.com",
                        },
                    },
                    {"title": "Unsupported", "id": "u", "k": "unsupported", "v": "x"},
                ],
            }
        ]
    }
    data, _ = build_export_data(account)
    fields = data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0][
        "fields"
    ]
    by_id = {field["id"]: field for field in fields}

    assert by_id["a"]["value"] == {
        "address": {
            "street": "1 Main",
            "city": "Springfield",
            "country": "US",
            "zip": "12345",
            "state": "CA",
        }
    }
    assert by_id["k"]["value"] == {
        "sshKey": {
            "privateKey": "priv",
            "metadata": {
                "privateKey": "priv",
                "publicKey": "pub",
                "fingerprint": "fp",
                "keyType": {"rsa": "Rsa2048"},
            },
        }
    }
    assert by_id["s"]["value"] == {
        "ssoLogin": {
            "provider": "okta",
            "item": {"itemUuid": "i", "vaultUuid": "v"},
        }
    }
    assert by_id["r"]["value"] == {"reference": '{"itemUuid": "i"}'}
    assert by_id["f"]["value"]["formattedText"] == {
        "content": "hi",
        "content_type": "Text",
        "content_format": "PlainText",
        "format_version": 1,
        "plain_text_display_value": "hi",
        "html_display_value": "<p>hi</p>",
    }
    assert by_id["m"]["value"] == {
        "managedApplication": {
            "applicationUuid": "app",
            "loginInitiationUrl": "https://example.com",
        }
    }
    assert by_id["u"]["value"] == {"unsupported": None}
    assert by_id["u"]["guarded"] is False
    assert by_id["u"]["multiline"] is False
    assert by_id["u"]["dontGenerate"] is False


def test_validator_rejects_partial_input_traits():
    from onedecrypt.pux_schema import _validate_input_traits

    with pytest.raises(SchemaError, match="missing field"):
        _validate_input_traits({"keyboard": "default"}, "traits")
    with pytest.raises(SchemaError, match="invalid enum value"):
        _validate_input_traits(
            {
                "keyboard": "bogus",
                "correction": "default",
                "capitalization": "default",
            },
            "traits",
        )


def test_minimal_item_matches_official_overview_and_details_invariants():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.details = {"sections": [{"title": "", "fields": [{"title": "F", "id": "f"}]}]}
    item.overview = {"title": "T"}
    data, _ = build_export_data(account)
    exported = data["accounts"][0]["vaults"][0]["items"][0]
    assert set(exported["overview"]) == {
        "title",
        "url",
        "subtitle",
        "icons",
        "watchtowerExclusions",
    }
    assert exported["overview"]["url"] == ""
    assert exported["overview"]["subtitle"] == ""
    assert exported["overview"]["icons"] is None
    assert exported["overview"]["watchtowerExclusions"] is None
    assert set(exported["details"]) == {
        "loginFields",
        "sections",
        "passwordHistory",
    }
    assert exported["details"]["loginFields"] == []
    assert exported["details"]["passwordHistory"] == []
    section = exported["details"]["sections"][0]
    assert section["title"] == ""
    assert "name" not in section
    field = section["fields"][0]
    assert set(field) == {
        "title",
        "id",
        "value",
        "guarded",
        "multiline",
        "dontGenerate",
        "inputTraits",
    }
    assert set(field["inputTraits"]) == {
        "keyboard",
        "correction",
        "capitalization",
    }


def test_placeholder_is_preserved_on_section_fields():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.details = {
        "sections": [
            {
                "title": "",
                "fields": [
                    {
                        "title": "F",
                        "id": "f",
                        "value": "v",
                        "placeholder": "hint",
                    }
                ],
            }
        ]
    }
    data, _ = build_export_data(account)
    field = data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0][
        "fields"
    ][0]
    assert field["placeholder"] == "hint"


def test_locations_are_wrapped_in_the_gps_variant():
    account = synthetic_account()
    account.vaults[0].key = b"x" * 32
    item = account.vaults[0].items[0]
    item.overview = {
        "title": "T",
        "locations": [
            {"id": "loc", "location": None},
            {"Gps": {"id": "loc2", "location": None}},
        ],
    }
    data, _ = build_export_data(account)
    overview = data["accounts"][0]["vaults"][0]["items"][0]["overview"]
    assert overview["locations"] == [
        {"Gps": {"id": "loc", "location": None}},
        {"Gps": {"id": "loc2", "location": None}},
    ]
