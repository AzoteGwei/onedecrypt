from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from helpers import synthetic_account
from onedecrypt.cli import main


def _make_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE accounts (account_uuid TEXT PRIMARY KEY, data BLOB NOT NULL);
        CREATE TABLE vaults (
            account_uuid TEXT NOT NULL,
            vault_uuid TEXT NOT NULL,
            data BLOB NOT NULL,
            PRIMARY KEY (account_uuid, vault_uuid)
        );
        CREATE TABLE items (
            account_uuid TEXT NOT NULL,
            vault_uuid TEXT NOT NULL,
            item_uuid TEXT NOT NULL,
            data BLOB NOT NULL,
            PRIMARY KEY (account_uuid, vault_uuid, item_uuid)
        );
        CREATE TABLE objects_associated (
            type INT NOT NULL,
            account_uuid TEXT NOT NULL,
            key_name TEXT NOT NULL,
            data BLOB NOT NULL,
            vault_uuid TEXT,
            item_uuid TEXT,
            PRIMARY KEY (type, account_uuid, key_name)
        );
        """
    )
    conn.execute(
        "INSERT INTO accounts VALUES (?, ?)",
        ("ACC1", json.dumps({"user_email": "a@example.com", "user_name": "A"}).encode()),
    )
    conn.commit()
    conn.close()


def test_self_test_command(capsys):
    assert main(["self-test"]) == 0
    assert "OK" in capsys.readouterr().out


def test_list_accounts_json(tmp_path: Path, capsys):
    db_path = tmp_path / "1password.sqlite"
    _make_db(db_path)
    assert main(["--db", str(db_path), "list-accounts", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["uuid"] == "ACC1"
    assert payload[0]["email"] == "a@example.com"


def test_decrypt_end_to_end_synthetic_database(tmp_path: Path):
    account = synthetic_account()
    db_path = tmp_path / "1password.sqlite"
    _make_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM accounts WHERE account_uuid = 'ACC1'")
    conn.execute(
        "INSERT INTO accounts VALUES (?, ?)",
        (account.uuid, json.dumps(account.data).encode()),
    )
    for keyset in account.keysets:
        conn.execute(
            "INSERT INTO objects_associated VALUES (?, ?, ?, ?, NULL, NULL)",
            (36, account.uuid, keyset.uuid, json.dumps(keyset.data).encode()),
        )
    for vault in account.vaults:
        conn.execute(
            "INSERT INTO vaults VALUES (?, ?, ?)",
            (account.uuid, vault.uuid, json.dumps(vault.data).encode()),
        )
        for item in vault.items:
            conn.execute(
                "INSERT INTO items VALUES (?, ?, ?, ?)",
                (account.uuid, vault.uuid, item.uuid, json.dumps(item.data).encode()),
            )
    conn.commit()
    conn.close()

    out = tmp_path / "rescue.1pux"
    assert (
        main(
            [
                "--db",
                str(db_path),
                "decrypt",
                "--account",
                "nobody@example.com",
                "--secret-key",
                "A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB",
                "--password",
                "update-clown-squid-bedpost",
                "--out",
                str(out),
                "--no-files",
            ]
        )
        == 0
    )
    with zipfile.ZipFile(out) as zf:
        exported = json.loads(zf.read("export.data"))
    item = exported["accounts"][0]["vaults"][0]["items"][0]
    assert item["details"]["loginFields"][1]["value"] == "secret"
    assert item["overview"]["title"] == "Example"
