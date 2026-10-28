"""Build an official-schema 1PUX v3 archive from decrypted B5 rows.

The serializer follows the desktop exporter's
``op_import_export::models::translation::onepux::v3`` structures.  In
particular:

* ``InnerVaultItem`` has exactly eight fields (no ``trashed``/``changerUuid``).
* ``ItemDetails`` has eight fields and uses long-form section fields.
* ``ItemOverview`` has the full v3 field set.
* ``export.attributes`` uses ``timestamp`` (not the doc example's
  ``createdAt``).
* ``official`` is the exporter/importer intersection, ``importer`` and
  ``exporter`` expose their respective code-supported field sets, and
  ``full`` keeps all local metadata including passkeys.
"""

from __future__ import annotations

import copy
import json
import time
import warnings
import zipfile
from pathlib import Path
from typing import Any

from .crypto import DecryptionError
from .database import Account, Item, Vault
from .documents import extract_document
from .pux_schema import (
    PROFILE_FULL,
    PROFILE_IMPORTER,
    PROFILE_OFFICIAL,
    PROFILES,
    validate_attributes,
    validate_export_data,
)

STATE_ACTIVE = 0
STATE_ARCHIVED = 1
STATE_DELETED = 2

_FIELD_BOOLS = {"guarded", "multiline", "dontGenerate"}
_FIELD_INTS = {"indexAtSource"}
_FIELD_STRINGS = {"placeholder", "clipboardFilter"}


def item_state(value: object) -> str:
    if value == STATE_ARCHIVED:
        return "archived"
    if value == STATE_DELETED:
        return "deleted"
    return "active"


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"yes", "true", "1", "y", "on"}
    return False


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


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


def _typed_value(kind: str | None, value: object) -> object:
    if isinstance(value, dict):
        return value
    if kind:
        # B5 SectionFieldValue is a tagged object; the 1PUX importer accepts
        # the same tagged shape.  Keep unknown tags as-is so no data is lost.
        return {kind: value}
    return value


def _convert_input_traits(traits: object) -> dict:
    if not isinstance(traits, dict):
        return {}
    result = {}
    if "keyboard" in traits:
        result["keyboard"] = str(traits["keyboard"])
    correction = traits.get("correction", traits.get("autocorrection"))
    capitalization = traits.get("capitalization", traits.get("autocapitalization"))
    if correction is not None:
        result["correction"] = str(correction)
    if capitalization is not None:
        result["capitalization"] = str(capitalization)
    return result


def _convert_section_field(field: object) -> dict | None:
    if not isinstance(field, dict):
        return None
    title = field.get("title", field.get("t", ""))
    field_id = field.get("id", field.get("n", ""))
    kind = field.get("k")
    if "value" in field:
        value = field["value"]
    elif "v" in field:
        value = _typed_value(kind, field["v"])
    else:
        value = None

    result: dict[str, Any] = {"title": str(title or ""), "id": str(field_id or "")}
    if value is not None:
        result["value"] = value

    attributes = field.get("a")
    if not isinstance(attributes, dict):
        attributes = {}
    for key in ("guarded", "multiline", "dontGenerate"):
        if key in field:
            result[key] = _as_bool(field[key])
        elif key in attributes:
            result[key] = _as_bool(attributes[key])
    if "indexAtSource" in field:
        parsed = _as_int(field["indexAtSource"])
        if parsed is not None:
            result["indexAtSource"] = parsed
    elif "indexAtSource" in attributes:
        parsed = _as_int(attributes["indexAtSource"])
        if parsed is not None:
            result["indexAtSource"] = parsed
    for key in ("placeholder", "clipboardFilter"):
        if key in field:
            result[key] = str(field[key])
        elif key in attributes:
            result[key] = str(attributes[key])

    input_traits = field.get("inputTraits")
    if input_traits is None:
        input_traits = attributes.get("inputTraits")
    converted_traits = _convert_input_traits(input_traits)
    if converted_traits:
        result["inputTraits"] = converted_traits
    return result


def _convert_section(section: object) -> dict | None:
    if not isinstance(section, dict):
        return None
    result: dict[str, Any] = {}
    if "title" in section:
        result["title"] = str(section["title"])
    if "name" in section:
        result["name"] = str(section["name"])
    fields = section.get("fields")
    if isinstance(fields, list):
        result["fields"] = [f for f in (_convert_section_field(item) for item in fields) if f]
    else:
        result["fields"] = []
    hidden = section.get("hideAddAnotherField")
    if hidden is None and isinstance(section.get("attributes"), dict):
        hidden = section["attributes"].get("hideAddAnotherField")
    if hidden is not None:
        result["hideAddAnotherField"] = _as_bool(hidden)
    return result


def _convert_login_field(field: object) -> dict | None:
    if not isinstance(field, dict):
        return None
    field_type = field.get("fieldType", field.get("type", field.get("t", "T")))
    result = {
        "value": _value_to_text(field.get("value", field.get("v", ""))),
        "id": str(field.get("id", "") or ""),
        "name": str(field.get("name", field.get("n", "")) or ""),
        "fieldType": str(field_type or "T"),
    }
    designation = field.get("designation")
    if designation in ("username", "password"):
        result["designation"] = designation
    return result


def _convert_login_fields(fields: object) -> list[dict]:
    if not isinstance(fields, list):
        return []
    return [f for f in (_convert_login_field(item) for item in fields) if f]


def _convert_html_form(form: object) -> dict | None:
    if not isinstance(form, dict):
        return None
    result = {}
    for key in ("htmlMethod", "htmlAction", "htmlID", "htmlName"):
        if key in form:
            result[key] = str(form[key])
        elif key == "htmlID" and "htmlId" in form:
            result[key] = str(form["htmlId"])
    return result or None


def _convert_password_history(history: object) -> list[dict]:
    if not isinstance(history, list):
        return []
    result = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        value = entry.get("value", entry.get("v"))
        timestamp = entry.get("time", entry.get("t"))
        if value is None or timestamp is None:
            continue
        result.append({"value": _value_to_text(value), "time": _as_int(timestamp) or 0})
    return result


def _convert_document_attributes(attrs: object, document_size: int | None) -> dict | None:
    if not isinstance(attrs, dict):
        return None
    document_id = attrs.get("documentId") or attrs.get("document_id")
    if not document_id:
        return None
    size = document_size
    if size is None:
        size = attrs.get("decryptedSize")
    if size is None:
        size = attrs.get("unencryptedSize")
    result = {
        "fileName": str(attrs.get("fileName") or attrs.get("file_name") or document_id),
        "documentId": str(document_id),
    }
    parsed_size = _as_int(size)
    if parsed_size is not None:
        result["decryptedSize"] = parsed_size
    return result


def _normalize_details(
    details: dict,
    category_uuid: str,
    document_size: int | None = None,
    profile: str = PROFILE_OFFICIAL,
) -> dict:
    """Convert decrypted B5 details into the selected 1PUX profile."""
    if not isinstance(details, dict):
        return {}
    if profile == PROFILE_FULL:
        return copy.deepcopy(details)
    result: dict[str, Any] = {}

    html_form = _convert_html_form(details.get("htmlForm"))
    if html_form:
        result["htmlForm"] = html_form

    login_fields = _convert_login_fields(
        details.get("loginFields") or details.get("fields")
    )
    if login_fields:
        result["loginFields"] = login_fields

    notes = details.get("notesPlain")
    if isinstance(notes, str) and notes:
        result["notesPlain"] = notes

    sections = details.get("sections")
    if isinstance(sections, list):
        converted_sections = [s for s in (_convert_section(item) for item in sections) if s]
        if converted_sections:
            result["sections"] = converted_sections

    history = _convert_password_history(details.get("passwordHistory"))
    if history:
        result["passwordHistory"] = history

    password = details.get("password")
    if isinstance(password, str) and password:
        result["password"] = password

    document_attributes = _convert_document_attributes(
        details.get("documentAttributes"), document_size
    )
    if document_attributes:
        result["documentAttributes"] = document_attributes

    passkey = details.get("passkey")
    if profile == PROFILE_IMPORTER and isinstance(passkey, dict):
        result["passkey"] = copy.deepcopy(passkey)
    return result


def _convert_url(url: object) -> dict | None:
    if not isinstance(url, dict):
        return None
    target = url.get("url", url.get("u", ""))
    if not target:
        return None
    result = {"label": str(url.get("label", url.get("l", "")) or ""), "url": str(target)}
    mode = url.get("mode")
    if mode:
        result["mode"] = str(mode)
    return result


def _normalize_overview(
    overview: dict,
    details: dict,
    category_uuid: str,
    profile: str = PROFILE_OFFICIAL,
) -> dict:
    source = overview if isinstance(overview, dict) else {}
    if profile == PROFILE_FULL:
        return copy.deepcopy(source)
    result: dict[str, Any] = {"title": str(source.get("title", "") or "")}

    url = source.get("url")
    if url:
        result["url"] = str(url)
    urls = source.get("urls")
    if isinstance(urls, list):
        converted_urls = [u for u in (_convert_url(item) for item in urls) if u]
        if converted_urls:
            result["urls"] = converted_urls
    tags = source.get("tags")
    if isinstance(tags, list) and tags:
        result["tags"] = [str(tag) for tag in tags]
    for key in ("ps", "pbe", "pgrng"):
        if key in source and source[key] is not None:
            result[key] = source[key]

    subtitle = source.get("subtitle") or source.get("ainfo") or ""
    if not subtitle and category_uuid in ("001", "005"):
        for field in details.get("loginFields", []):
            if field.get("designation") == "username":
                subtitle = field.get("value") or ""
                break
    if subtitle:
        result["subtitle"] = str(subtitle)

    for key in (
        "icons",
        "passkey",
        "passkeyId",
        "shortcut",
        "locations",
        "b5UserUUID",
        "watchtowerExclusions",
        "appIds",
    ):
        if key not in source or source[key] in (None, [], {}):
            continue
        if key in ("passkey", "passkeyId") and profile != PROFILE_IMPORTER:
            continue
        if key == "icons" and not isinstance(source[key], dict):
            continue
        result[key] = source[key]
    return result


def _normalize_item(
    item: Item,
    document_size: int | None = None,
    profile: str = PROFILE_OFFICIAL,
) -> dict:
    data = item.data
    category_uuid = str(data.get("category_uuid", ""))
    details = _normalize_details(item.details or {}, category_uuid, document_size, profile)
    if profile == PROFILE_FULL:
        overview = copy.deepcopy(item.overview or {})
    else:
        overview = _normalize_overview(item.overview or {}, details, category_uuid, profile)
    result = {
        "uuid": item.uuid,
        "favIndex": 1 if data.get("is_favorite") else 0,
        "createdAt": _as_int(data.get("created_at")) or 0,
        "updatedAt": _as_int(data.get("updated_at")) or 0,
        "state": item_state(data.get("state")),
        "categoryUuid": category_uuid,
        "details": details,
        "overview": overview,
    }
    if profile == PROFILE_FULL:
        result["trashed"] = "D" if result["state"] == "deleted" else "N"
        result["stateRaw"] = data.get("state")
        if "validated" in data:
            result["validated"] = data["validated"]
        if "changer_uuid" in data:
            result["changerUuid"] = data["changer_uuid"]
        if "scope" in (item.overview or {}):
            result["scope"] = item.overview["scope"]
    return result


def _normalize_vault(vault: Vault) -> dict:
    attrs = dict(vault.attrs or {})
    name = attrs.get("name") or f"Vault {vault.uuid[:6]}"
    desc = attrs.get("desc", attrs.get("description", ""))
    avatar = attrs.get("avatar", attrs.get("icon", "") if isinstance(attrs.get("icon"), str) else "")
    return {
        "uuid": vault.uuid,
        "desc": str(desc or ""),
        "avatar": str(avatar or ""),
        "name": str(name),
        "type": str(vault.type or "U"),
    }


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
    profile: str = PROFILE_OFFICIAL,
) -> tuple[dict, dict[str, bytes]]:
    """Return (export.data, files) for one decrypted account."""
    if profile not in PROFILES:
        raise ValueError(f"unknown schema profile {profile!r}")
    vaults = []
    files: dict[str, bytes] = {}
    for vault in account.vaults:
        if vault.key is None:
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
            normalized = _normalize_item(item, document_size, profile)
            items.append(normalized)
            if document is not None:
                file_name, content = document
                document_id = (item.details or {}).get("documentAttributes", {}).get("documentId") or ""
                if document_id:
                    files[f"files/{document_id}___{file_name}"] = content
        vaults.append({"attrs": _normalize_vault(vault), "items": items})
    data = {"accounts": [{"attrs": _normalize_account(account), "vaults": vaults}]}
    validate_export_data(data, profile)
    return data, files


def write_1pux(
    path: str | Path,
    account: Account,
    files_dir: Path | None = None,
    profile: str = PROFILE_OFFICIAL,
) -> tuple[Path, int, int]:
    """Write a 1PUX file using the selected schema profile."""
    path = Path(path)
    data, files = build_export_data(account, files_dir, profile)
    attributes = {
        "version": 3,
        "description": "1Password Unencrypted Export",
        "timestamp": int(time.time()),
    }
    validate_attributes(attributes)
    path.parent.mkdir(parents=True, exist_ok=True)
    item_count = sum(len(v["items"]) for v in data["accounts"][0]["vaults"])
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("export.attributes", json.dumps(attributes, ensure_ascii=False, indent=2))
        zf.writestr("export.data", json.dumps(data, ensure_ascii=False, indent=2))
        for name, content in files.items():
            zf.writestr(name, content)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path, item_count, len(files)


def dump_account_json(account: Account, profile: str = PROFILE_OFFICIAL) -> dict:
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
                "items": [_normalize_item(item, profile=profile) for item in vault.items],
            }
            for vault in account.vaults
        ],
    }
