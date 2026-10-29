"""Command-line entry point for the offline 1Password database decryptor."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .crypto import DecryptionError, derive_muk, jwe_decrypt, parse_secret_key
from .database import Account, LocalDatabase, find_account, load_items
from .decrypt import decrypt_account
from .pux import dump_account_json, write_1pux
from .pux_schema import PROFILE_OFFICIAL, PROFILES

DEFAULT_DB = Path.home() / ".config" / "1Password" / "1password.sqlite"


def _progress(verbose: bool):
    def emit(message: str) -> None:
        if verbose:
            print(message, file=sys.stderr)

    return emit


def _account_line(account: Account) -> str:
    item_count = sum(len(vault.items) for vault in account.vaults)
    return (
        f"{account.email or '(no email)'}  "
        f"{account.name or account.team_name or '(no name)'}  "
        f"{account.uuid}  "
        f"{len(account.vaults)} vault(s), {item_count} item(s)"
    )


def _choose_account(accounts: list[Account], query: str | None) -> Account:
    if not accounts:
        raise SystemExit("the database contains no accounts")
    if query:
        return find_account(accounts, query)
    if len(accounts) == 1:
        return accounts[0]
    print("Multiple accounts are present in this database:", file=sys.stderr)
    for index, account in enumerate(accounts, 1):
        print(f"  [{index}] {_account_line(account)}", file=sys.stderr)
    while True:
        answer = input("Select an account number: ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(accounts):
            return accounts[int(answer) - 1]
        try:
            return find_account(accounts, answer)
        except SystemExit:
            print("Please enter a valid number, email address, or account UUID.", file=sys.stderr)


def cmd_list_accounts(args: argparse.Namespace) -> int:
    with LocalDatabase(args.db) as db:
        accounts = db.accounts()
        if not accounts:
            print("No accounts found.", file=sys.stderr)
            return 1
        records = []
        for account in accounts:
            items = 0
            for vault in account.vaults:
                items += sum(1 for _ in db.items(account.uuid, vault.uuid))
            records.append(
                {
                    "uuid": account.uuid,
                    "email": account.email,
                    "name": account.name,
                    "teamName": account.team_name,
                    "signInUrl": account.data.get("sign_in_url", ""),
                    "vaults": len(account.vaults),
                    "items": items,
                }
            )
        if args.format == "json":
            print(json.dumps(records, ensure_ascii=False, indent=2))
        else:
            for record in records:
                print(
                    f"{record['email'] or '(no email)'}\t"
                    f"{record['name'] or record['teamName']}\t"
                    f"{record['uuid']}\t"
                    f"{record['vaults']} vault(s), {record['items']} item(s)"
                )
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    progress = _progress(args.verbose)
    secret_key_input = args.secret_key
    if not secret_key_input:
        secret_key_input = getpass.getpass("Secret Key (A3-...): ")
    try:
        parse_secret_key(secret_key_input)
    except ValueError as exc:
        print(f"Invalid Secret Key: {exc}", file=sys.stderr)
        return 2

    password = args.password
    if password is None:
        password = getpass.getpass("Master Password: ")

    with LocalDatabase(args.db) as db:
        accounts = db.accounts()
        account = _choose_account(accounts, args.account)
        progress(f"selected account {account.email} ({account.uuid})")
        load_items(account, db)
        try:
            decrypt_account(account, secret_key_input, password, progress=progress)
        except DecryptionError as exc:
            print(f"Decryption failed: {exc}", file=sys.stderr)
            print(
                "Check that the Secret Key and Master Password belong to the selected "
                "account.  No data was modified.",
                file=sys.stderr,
            )
            return 3

        if args.check:
            unlocked_vaults = len(account.vaults) - len(account.failed_vaults)
            item_count = sum(len(vault.items) for vault in account.vaults)
            print(
                f"Credentials OK: {unlocked_vaults} vault(s), "
                f"{item_count - len(account.failed_items)} item(s) decrypted, "
                f"{len(account.failed_items)} item failure(s)."
            )
            return 0 if unlocked_vaults else 4

        if args.no_files:
            files_dir = None
        elif args.files_dir:
            files_dir = Path(args.files_dir).expanduser()
        else:
            files_dir = Path(args.db).expanduser().parent / "files"
        if files_dir is not None and not files_dir.exists():
            print(f"warning: files directory not found: {files_dir}", file=sys.stderr)
            files_dir = None

        if not any(vault.key is not None for vault in account.vaults):
            print(
                "No vault could be unlocked; refusing to write an empty export.",
                file=sys.stderr,
            )
            return 4

        out = Path(args.out).expanduser() if args.out else Path.cwd() / f"{account.uuid}.1pux"
        path, item_count, file_count = write_1pux(
            out,
            account,
            files_dir,
            profile=args.schema_profile,
            shape_report_path=args.shape_report,
        )
        print(f"Wrote {path} ({item_count} items, {file_count} document file(s))")
        if account.failed_vaults:
            print(
                f"warning: {len(account.failed_vaults)} vault(s) could not be unlocked "
                "and were omitted from the export; rerun with --verbose for details",
                file=sys.stderr,
            )
            if args.verbose:
                for vault_uuid, message in account.failed_vaults:
                    print(f"  vault {vault_uuid}: {message}", file=sys.stderr)
        if account.failed_items:
            print(
                f"warning: {len(account.failed_items)} item(s) could not be decrypted "
                "and were exported without their encrypted body; rerun with --verbose "
                "for details",
                file=sys.stderr,
            )
            if args.verbose:
                for item_uuid, message in account.failed_items:
                    print(f"  {item_uuid}: {message}", file=sys.stderr)

        if args.dump_json:
            dump_path = Path(args.dump_json).expanduser()
            dump_path.write_text(
                json.dumps(
                    dump_account_json(account, profile=args.schema_profile),
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            try:
                dump_path.chmod(0o600)
            except OSError:
                pass
            print(f"Wrote {dump_path}")
    return 0


def cmd_self_test(_: argparse.Namespace) -> int:
    """Run the published 2SKD + AES-GCM test vector."""
    secret_key = "A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB"
    password = "update-clown-squid-bedpost"
    email = "nobody@example.com"
    expected = "6VIFjzKXaHctk44NXr8hOenpgwxWgZebtOlGkPwGK-Y="
    from .crypto import MukParams, b64d, b64u

    params = MukParams(alg="PBES2g-HS256", iterations=100000, salt="cA4f6QY7wwUoclj74RMvUg==")
    muk = derive_muk(secret_key, password, email, params)
    if b64u(muk) != expected.rstrip("="):
        print("FAIL: MUK test vector mismatch", file=sys.stderr)
        return 1

    # Keyset ciphertext from the same public test data.
    iv = b64d("2FF8mtGD55z84h9jMtWAyQ==")
    data = b64d(
        "8OjOA2NqUZZGxXD4r-z4QUfxjvuk23_i0DFAcYxx1r84hmsG1KV1G9iKBZd-kFpfzDgciJD3h8d91OT9D6F8KVqvdmx_q649mWEhiWwVcmRlKRVzgj-eZunS1XHxwHYDhvNvdzKUpNdAp7EKsQCRpiJJ3-eTndQBFMdyeCwkxnqMkuGW326P_mjW5yp_qYpGc4HgpY-_3aEhKimKVGJuxL4I5U5LU2ZFVNNhRIxkjJShtEwtXcTaVwH6"
    )
    plaintext = jwe_decrypt(muk, {"iv": b64u(iv), "data": b64u(data), "enc": "A256GCM"})
    if json.loads(plaintext).get("kid") != "qn8uimc4l7sofa26yivex24j7q":
        print("FAIL: keyset test vector mismatch", file=sys.stderr)
        return 1
    print("OK: 2SKD MUK and A256GCM test vectors match")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="onedecrypt",
        description="Decrypt a local 1Password 8 1password.sqlite and rebuild a 1PUX export.",
    )
    parser.add_argument("--db", default=str(DEFAULT_DB), help="path to 1password.sqlite")
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list-accounts", help="list accounts in the database")
    list_parser.add_argument("--format", choices=("table", "json"), default="table")
    list_parser.set_defaults(func=cmd_list_accounts)

    decrypt_parser = sub.add_parser("decrypt", help="decrypt one account and write a 1PUX")
    decrypt_parser.add_argument("--account", help="account email, name, or UUID")
    decrypt_parser.add_argument("--secret-key", help="Secret Key (prompted if omitted)")
    decrypt_parser.add_argument("--password", help="Master Password (prompted if omitted)")
    decrypt_parser.add_argument("--out", help="output .1pux path")
    decrypt_parser.add_argument("--dump-json", help="also write a plaintext JSON debug dump")
    decrypt_parser.add_argument(
        "--shape-report",
        help="write a value-free JSON type report for debugging import errors",
    )
    decrypt_parser.add_argument(
        "--files-dir",
        default=None,
        help="1Password document cache directory (default: <db directory>/files)",
    )
    decrypt_parser.add_argument("--no-files", action="store_true", help="do not include documents")
    decrypt_parser.add_argument(
        "--schema-profile",
        choices=sorted(PROFILES),
        default=PROFILE_OFFICIAL,
        help="1PUX schema profile (default: official)",
    )
    decrypt_parser.add_argument(
        "--check",
        action="store_true",
        help="verify the credentials and decryption without writing a 1PUX",
    )
    decrypt_parser.add_argument("--verbose", action="store_true")
    decrypt_parser.set_defaults(func=cmd_decrypt)

    test_parser = sub.add_parser("self-test", help="verify the cryptographic test vectors")
    test_parser.set_defaults(func=cmd_self_test)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
