from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from onedecrypt.database import LocalDatabase, find_account, load_items


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
    conn.execute(
        "INSERT INTO vaults VALUES (?, ?, ?)",
        ("ACC1", "V1", json.dumps({"vault_type": "P"}).encode()),
    )
    conn.execute(
        "INSERT INTO objects_associated VALUES (?, ?, ?, ?, NULL, NULL)",
        (36, "ACC1", "K1", json.dumps({"encryptedBy": "mp"}).encode()),
    )
    conn.execute(
        "INSERT INTO items VALUES (?, ?, ?, ?)",
        ("ACC1", "V1", "I1", json.dumps({"category_uuid": "001"}).encode()),
    )
    conn.commit()
    conn.close()


def test_reader_loads_rows_and_accounts(tmp_path: Path):
    db_path = tmp_path / "1password.sqlite"
    _make_db(db_path)
    with LocalDatabase(db_path) as db:
        accounts = db.accounts()
        assert len(accounts) == 1
        account = accounts[0]
        assert account.email == "a@example.com"
        assert [v.uuid for v in account.vaults] == ["V1"]
        assert [k.uuid for k in account.keysets] == ["K1"]
        load_items(account, db)
        assert [i.uuid for i in account.vaults[0].items] == ["I1"]


def test_find_account_by_email_and_uuid():
    class A:
        def __init__(self, uuid, email, name="", team_name=""):
            self.uuid, self.email, self.name, self.team_name = uuid, email, name, team_name

    accounts = [A("ACC1", "a@example.com", "A"), A("ACC2", "b@example.com", "B")]
    assert find_account(accounts, "a@example.com").uuid == "ACC1"
    assert find_account(accounts, "ACC2").uuid == "ACC2"
    with pytest.raises(SystemExit):
        find_account(accounts, "missing")
