from __future__ import annotations

from helpers import synthetic_account
from onedecrypt.decrypt import decrypt_account, resolve_keysets


def test_synthetic_keyset_graph_and_item_decryption():
    account = synthetic_account()
    resolved = resolve_keysets(
        account.keysets,
        "A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB",
        "update-clown-squid-bedpost",
        account.email,
    )
    assert set(resolved) == {"root", "child"}

    decrypt_account(
        account,
        "A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB",
        "update-clown-squid-bedpost",
    )
    assert account.vaults[0].attrs["name"] == "Personal"
    item = account.vaults[0].items[0]
    assert item.details["notesPlain"] == "note"
    assert item.overview["title"] == "Example"
