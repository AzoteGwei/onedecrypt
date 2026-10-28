"""Build a 1PUX (1Password Unencrypted Export) archive from decrypted rows.

The 1PUX container is a ZIP with ``export.attributes``, ``export.data`` and an
optional ``files/`` directory.  The item bodies are the decrypted B5 item
details/overview; we only translate the outer camelCase wrapper and the
legacy ``fields`` -> ``loginFields`` spelling used by 1PUX for Login items.
"""

from __future__ import annotations

import json
import time
import warnings
import zipfile
from pathlib import Path
from typing import Iterable

from .crypto import DecryptionError
from .database import Account, Item, Vault
from .documents import extract_document

# Database item state is an integer.  The desktop SQL uses
# ``data ->> '$.state' = 0`` for active items and ``!= 0`` for inactive ones;
# the other values distinguish archived (1) from deleted/trashed (2).
STATE_ACTIVE = 0
STATE_ARCHIVED = 1
STATE_DELETED = 2


def item_state(value: object) -> str:
    if value == STATE_ARCHIVED:
        return "archived"
    if value == STATE_DELETED:
        return "deleted"
    return "active"


def _value_to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        for key in ("concealed", "string", "email", "url", "phone", "value", "formattedText"):
            if key in value and not isinstance(value[key], dict):
                return str(value[key])
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _convert_fields(fields: Iterable[dict]) -> list[dict]:
    converted = []
    for field in fields:
        if not isinstance(field, dict):
            continue
        value = field.get("value", field.get("v"))
        converted.append(
            {
                "value": _value_to_text(value),
                "id": field.get("id", field.get("fieldId", "")),
                "name": field.get("name", field.get("n", "")),
                "fieldType": field.get("fieldType", field.get("type", field.get("t", "T"))),
                **(
                    {"designation": field["designation"]}
                    if field.get("designation") in ("username", "password")
                    else {}
                ),
            }
        )
    return converted


def _normalize_details(
    details: dict, category_uuid: str, document_size: int | None = None
) -> dict:
    """Translate the decrypted B5 details into the 1PUX details shape."""
    if not isinstance(details, dict):
        return {}
    result = dict(details)

    document_attributes = result.get("documentAttributes")
    if isinstance(document_attributes, dict):
        # The B5 record carries the per-file AES key, nonce and integrity hash
        # so the local file can be decrypted.  Those are not part of a 1PUX
        # document reference; keep only the fields the importer needs.
        clean = {
            "fileName": document_attributes.get("fileName", ""),
            "documentId": document_attributes.get("documentId", ""),
        }
        size = document_size
        if size is None:
            size = document_attributes.get("unencryptedSize")
        if size is None:
            size = document_attributes.get("decryptedSize")
        if size is not None:
            clean["decryptedSize"] = size
        result["documentAttributes"] = clean

    login_fields = result.get("loginFields")
    if isinstance(login_fields, list):
        result["loginFields"] = _convert_fields(login_fields)
    elif category_uuid == "001" and isinstance(result.get("fields"), list):
        result["loginFields"] = _convert_fields(result["fields"])
        # The B5 login field array is called ``fields``; 1PUX importers use
        # ``loginFields``.  Keep ``fields`` only for non-login categories.
        result.pop("fields", None)
    elif category_uuid == "005" and isinstance(result.get("password"), str):
        result["loginFields"] = [
            {
                "value": result["password"],
                "id": "",
                "name": "password",
                "fieldType": "P",
                "designation": "password",
            }
        ]

    sections = result.get("sections")
    if isinstance(sections, list):
        for section in sections:
            if not isinstance(section, dict):
                continue
            fields = section.get("fields")
            if isinstance(fields, list):
                for field in fields:
                    if isinstance(field, dict) and "fieldType" not in field and "type" in field:
                        field["fieldType"] = field["type"]
    return result


def _normalize_overview(overview: dict, details: dict, category_uuid: str) -> dict:
    result = dict(overview) if isinstance(overview, dict) else {}
    if "subtitle" not in result:
        subtitle = result.get("ainfo") or ""
        if not subtitle and category_uuid in ("001", "005"):
            for field in details.get("loginFields", []):
                if field.get("designation") == "username":
                    subtitle = field.get("value") or ""
                    break
        result["subtitle"] = subtitle
    for key in ("urls", "tags"):
        if result.get(key) is None:
            result[key] = []
    return result


def _normalize_item(item: Item, document_size: int | None = None) -> dict:
    data = item.data
    category_uuid = str(data.get("category_uuid", ""))
    details = _normalize_details(item.details or {}, category_uuid, document_size)
    overview = _normalize_overview(item.overview or {}, details, category_uuid)
    state = item_state(data.get("state"))
    result = {
        "uuid": item.uuid,
        "favIndex": 1 if data.get("is_favorite") else 0,
        "createdAt": data.get("created_at", 0),
        "updatedAt": data.get("updated_at", 0),
        "state": state,
        # Legacy 1PIF flag: N = normal, D = deleted.  Archived items are not
        # "trashed"; the 1PUX ``state`` field carries the archive distinction.
        "trashed": "D" if state == "deleted" else "N",
        "categoryUuid": category_uuid,
        "details": details,
        "overview": overview,
    }
    if "changer_uuid" in data:
        result["changerUuid"] = data["changer_uuid"]
    if "scope" in data:
        result["scope"] = data["scope"]
    return result


def _normalize_vault(vault: Vault) -> dict:
    attrs = dict(vault.attrs or {})
    vault_type = vault.type or attrs.get("type") or "U"
    attrs["uuid"] = vault.uuid
    if not attrs.get("name"):
        attrs["name"] = f"Vault {vault.uuid[:6]}"
    attrs.setdefault("desc", attrs.get("description", ""))
    attrs.setdefault("avatar", attrs.get("icon", "") if isinstance(attrs.get("icon"), str) else "")
    # 1PUX only defines P (personal), E (everyone/shared) and U (user-created).
    # Hidden/generated/shared system vaults are exported as user-created so the
    # items are not dropped by an importer.
    attrs["type"] = vault_type if vault_type in ("P", "E", "U") else "U"
    return attrs


def _normalize_account(account: Account) -> dict:
    data = account.data
    fallback = data.get("user_email") or account.uuid
    return {
        "accountName": data.get("team_name") or data.get("user_name") or fallback,
        "name": data.get("user_name") or data.get("team_name") or fallback,
        "avatar": data.get("team_avatar") or data.get("user_avatar") or "",
        "email": data.get("user_email") or "",
        "uuid": account.uuid,
        "domain": data.get("sign_in_url") or "",
    }


def build_export_data(
    account: Account,
    files_dir: Path | None = None,
) -> tuple[dict, dict[str, bytes]]:
    """Return (export.data, files) for one decrypted account."""
    vaults = []
    files: dict[str, bytes] = {}
    for vault in account.vaults:
        if vault.key is None:
            # Vault key could not be unlocked; its items are ciphertext only.
            continue
        items = []
        for item in vault.items:
            try:
                document = extract_document(
                    item.details or {}, account.uuid, files_dir, fallback_key=vault.key
                )
            except (FileNotFoundError, DecryptionError, ValueError) as exc:
                warnings.warn(f"item {item.uuid}: {exc}", stacklevel=2)
                document = None
            document_size = len(document[1]) if document is not None else None
            normalized = _normalize_item(item, document_size)
            items.append(normalized)
            if document is not None:
                file_name, content = document
                document_id = (item.details or {}).get("documentAttributes", {}).get("documentId") or ""
                if document_id:
                    files[f"files/{document_id}___{file_name}"] = content
        vaults.append({"attrs": _normalize_vault(vault), "items": items})
    data = {"accounts": [{"attrs": _normalize_account(account), "vaults": vaults}]}
    return data, files


def write_1pux(
    path: str | Path,
    account: Account,
    files_dir: Path | None = None,
) -> tuple[Path, int, int]:
    """Write a 1PUX file and return (path, item_count, file_count)."""
    path = Path(path)
    data, files = build_export_data(account, files_dir)
    attributes = {
        "version": 3,
        "description": "1Password Unencrypted Export",
        "createdAt": int(time.time()),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    item_count = sum(len(v["items"]) for v in data["accounts"][0]["vaults"])
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("export.attributes", json.dumps(attributes, ensure_ascii=False, indent=2))
        zf.writestr("export.data", json.dumps(data, ensure_ascii=False, indent=2))
        for name, content in files.items():
            zf.writestr(name, content)
    # A 1PUX is a plaintext password dump; do not leave it world-readable.
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path, item_count, len(files)


def dump_account_json(account: Account) -> dict:
    """Return a plain JSON representation useful for debugging."""
    return {
        "account": {
            "uuid": account.uuid,
            "email": account.email,
            "name": account.name,
            "teamName": account.team_name,
            "attrs": _normalize_account(account),
        },
        "vaults": [
            {
                "uuid": vault.uuid,
                "attrs": _normalize_vault(vault),
                "items": [_normalize_item(item) for item in vault.items],
            }
            for vault in account.vaults
        ],
    }
