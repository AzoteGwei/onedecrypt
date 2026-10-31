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
import math
import re
import time
import warnings
import zipfile
from pathlib import Path
from typing import Any

from .crypto import DecryptionError
from .database import Account, Item, Vault
from .documents import (
    clean_file_reference,
    extract_file_reference,
    iter_file_references,
)
from .pux_schema import (
    PROFILE_EXPORTER,
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

# SectionFieldValue is an externally tagged enum in both the B5 model and the
# 1PUX importer.  Canonical output must always be an object with exactly one
# of these keys; a bare scalar fails serde before the item can be imported.
SECTION_VALUE_TAGS = {
    "address",
    "concealed",
    "creditCardNumber",
    "creditCardType",
    "date",
    "email",
    "file",
    "formattedText",
    "gender",
    "managedApplication",
    "menu",
    "monthYear",
    "phone",
    "reference",
    "sshKey",
    "ssoLogin",
    "string",
    "totp",
    "unsupported",
    "url",
}
SECTION_STRING_TAGS = {
    "concealed",
    "creditCardNumber",
    "creditCardType",
    "gender",
    "menu",
    "phone",
    "string",
    "totp",
    "url",
}
# The local B5 rows use the same camel-case tags as the official wire
# format, but some older rows spell the SSH tag as a local identifier.
SECTION_VALUE_ALIASES = {
    "ssh_key": "sshKey",
    "ssh-key": "sshKey",
    "privateKey": "sshKey",
    "private_key": "sshKey",
}
PASSWORD_LABEL_RE = re.compile(r"(?<![a-z0-9])(passphrase|password|pin)(?![a-z0-9])")
WATCHTOWER_KEYS = {
    "compromised",
    "vulnerable",
    "reused",
    "weak",
    "unsecured",
    "inactiveMfa",
    "expiring",
    "lastpass",
    "wrongAccount",
    "passkeyAvailable",
    "duplicateItem",
    "conflictingShortcut",
}
MIGRATION_KEYS = ("itemUuid", "accountUuid", "vaultUuid")


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


def _section_text(value: object) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return _value_to_text(value)


def _text_value(value: object, default: str = "") -> str:
    """Coerce a scalar-ish value to text without dumping JSON for objects."""
    if isinstance(value, str):
        return value
    if value is None:
        return default
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return default


def _normalize_address(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    return {
        "street": _text_value(
            value.get("street", value.get("streetAddress", value.get("street_address")))
        ),
        "city": _text_value(value.get("city")),
        "country": _text_value(value.get("country", value.get("territory"))),
        "zip": _text_value(value.get("zip", value.get("postalCode"))),
        "state": _text_value(value.get("state", value.get("territory"))),
    }


RSA_KEY_SIZES = {
    "2048": "Rsa2048",
    "3072": "Rsa3072",
    "4096": "Rsa4096",
    "rsa2048": "Rsa2048",
    "rsa3072": "Rsa3072",
    "rsa4096": "Rsa4096",
    "rsa_2048": "Rsa2048",
    "rsa_3072": "Rsa3072",
    "rsa_4096": "Rsa4096",
    "rsa-2048": "Rsa2048",
    "rsa-3072": "Rsa3072",
    "rsa-4096": "Rsa4096",
    "rsaunsupported": "RsaUnsupported",
    "unsupported": "RsaUnsupported",
}


def _normalize_rsa_size(value: object) -> str:
    if isinstance(value, dict):
        value = value.get("bits", value.get("size", value.get("keySize")))
    return RSA_KEY_SIZES.get(_text_value(value).strip().lower(), "RsaUnsupported")


def _normalize_key_type(value: object) -> str | dict:
    """Normalize op_ssh_key_types::SshKeyType.

    The wire enum is externally tagged: the unit variant serializes as
    ``"ed25519"`` and the ``rsa`` variant as ``{"rsa": "<RsaKeySize>"}``.
    ``RsaKeySize`` serializes as ``Rsa2048``/``Rsa3072``/``Rsa4096``/
    ``RsaUnsupported``.
    """
    if isinstance(value, dict):
        if "rsa" in value:
            return {"rsa": _normalize_rsa_size(value["rsa"])}
        if "ed25519" in value:
            return "ed25519"
        variant = _text_value(value.get("type", value.get("variant"))).strip().lower()
        if variant == "rsa":
            return {"rsa": _normalize_rsa_size(value)}
        return "ed25519"
    text = _text_value(value).strip()
    lowered = text.lower()
    if not lowered or lowered in {"ed25519", "ed-25519", "ed 25519"}:
        return "ed25519"
    if lowered == "rsa" or lowered.startswith("rsa"):
        return {"rsa": _normalize_rsa_size(lowered)}
    return "ed25519"


def _looks_like_private_key(value: object) -> bool:
    """Return true for private-key text or an object carrying one."""
    if isinstance(value, dict):
        if any(key in value for key in ("privateKey", "private_key")):
            return True
        if len(value) == 1:
            only, inner = next(iter(value.items()))
            if only in (
                "sshKey",
                "concealed",
                "string",
                "privateKey",
                "private_key",
            ):
                return _looks_like_private_key(inner)
        return False
    if not isinstance(value, str):
        return False
    head = value.lstrip()[:80]
    return head.startswith("-----BEGIN ") and "PRIVATE KEY-----" in head


def _normalize_ssh_key(value: object) -> dict | None:
    """Normalize a local SSH key field value.

    The official wire value is ``{"privateKey": ..., "metadata": {...}}``.
    Local B5 rows can store the same object, a bare private-key string, or a
    flat object with ``privateKey``/``publicKey``/``fingerprint``/``keyType``.
    The importer can derive the metadata when it is absent, so ``metadata`` is
    only emitted when the source actually contains it.
    """
    if isinstance(value, dict) and len(value) == 1:
        only, wrapped = next(iter(value.items()))
        if only in ("sshKey", "concealed", "string", "privateKey", "private_key"):
            value = wrapped
    if isinstance(value, str):
        private_key = value
        inner: dict = {}
    elif isinstance(value, dict):
        inner = value.get("sshKey") if isinstance(value.get("sshKey"), dict) else value
        private_key = _text_value(
            inner.get("privateKey", inner.get("private_key", inner.get("value")))
        )
    else:
        return None

    metadata = inner.get("metadata")
    flat_metadata = any(
        key in inner
        for key in (
            "publicKey",
            "public_key",
            "fingerprint",
            "keyType",
            "key_type",
        )
    )
    if not isinstance(metadata, dict) and flat_metadata:
        metadata = inner
    if not isinstance(metadata, dict):
        metadata = None

    if metadata is not None:
        metadata_private = _text_value(
            metadata.get("privateKey", metadata.get("private_key")),
            private_key,
        )
        if not private_key:
            private_key = metadata_private
        if not private_key:
            return None
        return {
            "privateKey": private_key,
            "metadata": {
                "privateKey": metadata_private or private_key,
                "publicKey": _text_value(
                    metadata.get("publicKey", metadata.get("public_key"))
                ),
                "fingerprint": _text_value(metadata.get("fingerprint")),
                "keyType": _normalize_key_type(
                    metadata.get("keyType", metadata.get("key_type"))
                ),
            },
        }

    if not private_key:
        return None
    return {"privateKey": private_key}


def _normalize_sso_login(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {"provider": _text_value(value.get("provider"))}
    item = value.get("item")
    if isinstance(item, dict):
        item_uuid = _text_value(
            item.get("itemUuid", item.get("item_uuid", item.get("uuid")))
        )
        vault_uuid = _text_value(item.get("vaultUuid", item.get("vault_uuid")))
        if item_uuid and vault_uuid:
            result["item"] = {"itemUuid": item_uuid, "vaultUuid": vault_uuid}
    return result


CONTENT_TYPES = {"text": "Text", "lexical": "Lexical"}
CONTENT_FORMATS = {
    "formattedtext": "FormattedText",
    "formatted_text": "FormattedText",
    "plaintext": "PlainText",
    "plain_text": "PlainText",
}


def _normalize_formatted_text(value: object) -> dict:
    if not isinstance(value, dict):
        value = {"content": _section_text(value)}
    content = _text_value(
        value.get(
            "content",
            value.get("plain_text_display_value", value.get("plainTextDisplayValue")),
        )
    )
    content_type = _text_value(
        value.get("content_type", value.get("contentType")), "Text"
    )
    content_type = CONTENT_TYPES.get(content_type.strip().lower(), "Text")
    content_format = _text_value(
        value.get("content_format", value.get("contentFormat")), "PlainText"
    )
    content_format = CONTENT_FORMATS.get(
        content_format.strip().lower(), "PlainText"
    )
    format_version = _as_int(
        value.get("format_version", value.get("formatVersion"))
    )
    plain = _text_value(
        value.get(
            "plain_text_display_value",
            value.get("plainTextDisplayValue", content),
        )
    )
    html = _text_value(
        value.get("html_display_value", value.get("htmlDisplayValue", plain))
    )
    return {
        "content": content,
        "content_type": content_type,
        "content_format": content_format,
        "format_version": 0 if format_version is None else format_version,
        "plain_text_display_value": plain,
        "html_display_value": html,
    }


def _normalize_managed_application(value: object) -> dict:
    if not isinstance(value, dict):
        value = {}
    return {
        "applicationUuid": _text_value(
            value.get(
                "applicationUuid",
                value.get(
                    "applicationUUID",
                    value.get("application_uuid", value.get("uuid")),
                ),
            )
        ),
        "loginInitiationUrl": _text_value(
            value.get(
                "loginInitiationUrl",
                value.get(
                    "loginInitiationURL",
                    value.get("login_initiation_url", value.get("url")),
                ),
            )
        ),
    }


def _normalize_section_value(kind: object, value: object) -> object:
    """Return a valid externally tagged SectionFieldValue object.

    The official importer deserializes ``value`` as an externally tagged enum
    with typed inner payloads.  B5 rows sometimes store a bare scalar, and
    several variants use nested object shapes.  Normalize those shapes here so
    serde does not reject the whole data model.
    """
    tag = None
    if isinstance(kind, str):
        candidate = SECTION_VALUE_ALIASES.get(kind, kind)
        if candidate in SECTION_VALUE_TAGS:
            tag = candidate

    # B5 rows and synthetic fixtures may already store the externally tagged
    # object.  Unwrap it before normalizing the payload.
    if isinstance(value, dict) and len(value) == 1:
        only = next(iter(value))
        cooked = SECTION_VALUE_ALIASES.get(only, only)
        if cooked in SECTION_VALUE_TAGS and (tag is None or cooked == tag):
            tag = cooked
            value = value[only]

    # A bare PEM private key is an SSH key even when an older row lost its
    # kind tag.  The importer derives the public key/fingerprint when metadata
    # is absent.
    if tag is None and _looks_like_private_key(value):
        tag = "sshKey"

    if tag == "file":
        if isinstance(value, dict):
            inner = value.get("file") if isinstance(value.get("file"), dict) else value
            if inner.get("fileName") and inner.get("documentId"):
                return {
                    "file": {
                        "fileName": _text_value(inner.get("fileName")),
                        "documentId": _text_value(inner.get("documentId")),
                        "decryptedSize": _as_int(
                            inner.get("decryptedSize", inner.get("unencryptedSize"))
                        )
                        or 0,
                    }
                }
        return {"string": _section_text(value)}

    if tag == "email":
        if isinstance(value, dict):
            address = (
                value.get("email_address")
                or value.get("emailAddress")
                or value.get("email")
                or value.get("address")
                or ""
            )
            provider = value.get("provider")
        else:
            address = _value_to_text(value)
            provider = None
        return {
            "email": {
                "email_address": _text_value(address),
                "provider": None if provider is None else _text_value(provider),
            }
        }

    if tag in ("date", "monthYear"):
        if value is None:
            return {tag: None}
        return {tag: _as_int(value)}

    if tag == "address":
        address = _normalize_address(value)
        if address is not None:
            return {"address": address}
        return {"string": _section_text(value)}

    if tag == "sshKey":
        ssh_key = _normalize_ssh_key(value)
        if ssh_key is not None:
            return {"sshKey": ssh_key}
        return {"string": _section_text(value)}

    if tag == "ssoLogin":
        sso_login = _normalize_sso_login(value)
        if sso_login is not None:
            return {"ssoLogin": sso_login}
        return {"string": _section_text(value)}

    if tag in SECTION_STRING_TAGS:
        return {tag: _value_to_text(value)}

    if tag == "formattedText":
        return {"formattedText": _normalize_formatted_text(value)}

    if tag == "managedApplication":
        return {"managedApplication": _normalize_managed_application(value)}

    if tag == "reference":
        # The importer's ``reference`` variant is a newtype around ArcStr,
        # not an object.
        return {"reference": _section_text(value)}

    if tag == "unsupported":
        # Unit variant: it carries no payload.
        return {"unsupported": None}

    if isinstance(value, dict):
        present = [key for key in value if key in SECTION_VALUE_TAGS]
        if len(present) == 1:
            return _normalize_section_value(present[0], value[present[0]])
        return {"string": _section_text(value)}

    return {"string": _section_text(value)}


INPUT_KEYBOARDS = {
    "default": "default",
    "numberpad": "numberPad",
    "namephonepad": "namePhonePad",
    "emailaddress": "emailAddress",
    "numbersandpunctuation": "numbersAndPunctuation",
    "url": "uRL",
    "urlkeyboard": "uRL",
}
INPUT_CORRECTIONS = {
    "default": "default",
    "yes": "yes",
    "no": "no",
    "true": "yes",
    "false": "no",
    "on": "yes",
    "off": "no",
}
INPUT_CAPITALIZATIONS = {
    "default": "default",
    "none": "none",
    "words": "words",
    "sentences": "sentences",
    "allcharacters": "allCharacters",
    "all_characters": "allCharacters",
}


def _enum_text(value: object, allowed: dict[str, str]) -> str | None:
    return allowed.get(str(value).strip().lower())


INPUT_TRAIT_DEFAULTS = {
    "keyboard": "default",
    "correction": "default",
    "capitalization": "default",
}


def _convert_input_traits(traits: object) -> dict:
    """Return the full DetailSectionFieldInputTraits object.

    The importer's InputTraits struct has three non-Option fields, so a
    partial object fails with ``missing field``.  The official exporter always
    writes all three; values that are absent locally use the ``default`` enum
    variant.
    """
    result = dict(INPUT_TRAIT_DEFAULTS)
    if not isinstance(traits, dict):
        return result
    if "keyboard" in traits:
        value = _enum_text(traits["keyboard"], INPUT_KEYBOARDS)
        if value:
            result["keyboard"] = value
    correction = traits.get("correction", traits.get("autocorrection"))
    if correction is not None:
        value = _enum_text(correction, INPUT_CORRECTIONS)
        if value:
            result["correction"] = value
    capitalization = traits.get("capitalization", traits.get("autocapitalization"))
    if capitalization is not None:
        value = _enum_text(capitalization, INPUT_CAPITALIZATIONS)
        if value:
            result["capitalization"] = value
    return result


def _convert_section_field(
    field: object,
    file_info: dict[str, tuple[str, bytes]] | None = None,
    category_uuid: str = "",
) -> dict | None:
    if not isinstance(field, dict):
        return None
    title = field.get("title", field.get("t", ""))
    field_id = field.get("id", field.get("n", ""))
    kind = field.get("k", field.get("kind"))
    if isinstance(kind, str):
        kind = SECTION_VALUE_ALIASES.get(kind, kind)
    if "value" in field:
        value = field["value"]
    elif "v" in field:
        value = field["v"]
    else:
        value = None

    # The local model represents SSH keys as a SectionFieldValue variant.
    # Older B5 rows occasionally store the private key as plain/concealed
    # text or lose the kind tag.  Category 114 plus the value (PEM/privateKey)
    # or the field's id/title identify it.  Recover the typed variant so the
    # importer creates an SSH key element instead of a plain text field.  Do
    # not rewrite a passphrase or other password-like field that merely
    # mentions a private key; key-looking values still win over the label.
    if category_uuid == "114" and kind in (None, "string", "concealed"):
        label = f"{field_id} {title}".lower()
        password_like = PASSWORD_LABEL_RE.search(label) is not None
        if _looks_like_private_key(value) or (
            not password_like and "private" in label and "key" in label
        ):
            kind = "sshKey"

    if isinstance(value, dict):
        file_reference = value.get("file")
        nested = isinstance(file_reference, dict)
        if not nested and (value.get("documentId") or value.get("document_id")):
            file_reference = value
        if isinstance(file_reference, dict):
            document_id = file_reference.get("documentId") or file_reference.get("document_id")
            if document_id and file_info is not None:
                if str(document_id) not in file_info:
                    return None
                file_name, content = file_info[str(document_id)]
                value = {"file": clean_file_reference(file_reference, len(content))}

    if value is not None:
        value = _normalize_section_value(kind, value)

    attributes = field.get("a")
    if not isinstance(attributes, dict):
        attributes = {}
    result: dict[str, Any] = {"title": str(title or ""), "id": str(field_id or "")}
    # The official exporter always writes ``value`` and the three boolean
    # flags.  The importer treats them as defaulted/Option fields, but matching
    # the official shape keeps the output byte-for-byte comparable.
    result["value"] = (
        _normalize_section_value(kind, None) if value is None else value
    )
    result["guarded"] = _as_bool(field.get("guarded", attributes.get("guarded", False)))
    result["multiline"] = _as_bool(
        field.get("multiline", attributes.get("multiline", False))
    )
    result["dontGenerate"] = _as_bool(
        field.get("dontGenerate", attributes.get("dontGenerate", False))
    )
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
    result["inputTraits"] = _convert_input_traits(input_traits)
    return result


def _convert_section(
    section: object,
    file_info: dict[str, tuple[str, bytes]] | None = None,
    category_uuid: str = "",
) -> dict | None:
    if not isinstance(section, dict):
        return None
    result: dict[str, Any] = {"title": str(section.get("title", "") or "")}
    if "name" in section:
        result["name"] = str(section["name"])
    fields = section.get("fields")
    if isinstance(fields, list):
        result["fields"] = [
            f
            for f in (
                _convert_section_field(item, file_info, category_uuid) for item in fields
            )
            if f
        ]
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
    # The shipped exporter writes ``htmlId`` (lower-case d).  The importer
    # accepts both spellings, so accept ``htmlID`` as a local/legacy alias.
    for key in ("htmlMethod", "htmlAction", "htmlId", "htmlName"):
        if key in form:
            result[key] = str(form[key])
        elif key == "htmlId" and "htmlID" in form:
            result[key] = str(form["htmlID"])
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


def _convert_document_attributes(
    attrs: object,
    document_size: int | None,
    file_info: dict[str, tuple[str, bytes]] | None = None,
) -> dict | None:
    if not isinstance(attrs, dict):
        return None
    document_id = attrs.get("documentId") or attrs.get("document_id")
    if not document_id:
        return None
    if file_info is not None:
        if str(document_id) not in file_info:
            return None
        file_name, content = file_info[str(document_id)]
        return {
            "fileName": file_name,
            "documentId": str(document_id),
            "decryptedSize": len(content),
        }
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
    # DocumentAttributes.decryptedSize is a required u64 in the importer.
    result["decryptedSize"] = 0 if parsed_size is None else parsed_size
    return result


def _normalize_details(
    details: dict,
    category_uuid: str,
    document_size: int | None = None,
    profile: str = PROFILE_OFFICIAL,
    file_info: dict[str, tuple[str, bytes]] | None = None,
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
    result["loginFields"] = login_fields

    notes = details.get("notesPlain")
    if isinstance(notes, str) and notes:
        result["notesPlain"] = notes

    sections = details.get("sections")
    converted_sections: list[dict] = []
    if isinstance(sections, list):
        converted_sections = [
            s
            for s in (
                _convert_section(item, file_info, category_uuid) for item in sections
            )
            if s
        ]
    # The official exporter always writes these three arrays, possibly empty.
    result["sections"] = converted_sections

    result["passwordHistory"] = _convert_password_history(
        details.get("passwordHistory")
    )

    password = details.get("password")
    if isinstance(password, str) and password:
        result["password"] = password

    document_attributes = _convert_document_attributes(
        details.get("documentAttributes"), document_size, file_info
    )
    if document_attributes:
        result["documentAttributes"] = document_attributes

    # ``details.passkey`` is accepted by the importer's ItemDetails visitor
    # only through the force_none helper; the value is discarded before the
    # item model is built.  The exporter path never emits it either, so only
    # the raw ``full`` profile (which returns above) preserves local passkeys.
    return result


URL_MODES = {
    "default": "default",
    "anywhereonwebsite": "default",
    "anywhere": "default",
    "website": "default",
    "host": "host",
    "exact": "host",
    "exacthost": "host",
    "exact host": "host",
    "never": "never",
    "neveronwebsite": "never",
    "never on website": "never",
}
URL_MODE_INDEX = {0: "default", 1: "host", 2: "never"}


def _url_mode(value: object) -> str:
    if value is None or value == "" or isinstance(value, bool):
        return "default"
    if isinstance(value, int):
        return URL_MODE_INDEX.get(value, "default")
    return URL_MODES.get(str(value).strip().lower(), "default")


def _convert_url(url: object) -> dict | None:
    """Normalize one B5/1PUX URL entry.

    Canonical rows use an object with ``label``/``url``/``mode``.  Local and
    legacy rows may also use the short ``l``/``u``/``m`` keys, a bare URL
    string, or a two/three-element sequence.  Normalize those forms instead
    of dropping the entry; the canonical output always uses long keys.
    """
    label: object = ""
    target: object = ""
    mode: object = None
    if isinstance(url, dict):
        target = url.get("url", url.get("u", ""))
        label = url.get("label", url.get("l", ""))
        mode = url.get("mode", url.get("m"))
    elif isinstance(url, (list, tuple)):
        if len(url) >= 2:
            label, target = url[0], url[1]
            if len(url) >= 3:
                mode = url[2]
    elif isinstance(url, str):
        target = url
    if not isinstance(target, str) or not target:
        return None
    return {
        "label": _text_value(label),
        "url": target,
        "mode": _url_mode(mode),
    }


def _overview_urls(source: dict) -> list[dict]:
    """Return all canonical URL entries from an overview object.

    B5 rows may spell the field ``URLs`` while the 1PUX wire format uses
    ``urls``; the official importer treats them as aliases.  Prefer the
    canonical spelling and fall back to the legacy one.
    """
    for key in ("urls", "URLs"):
        values = source.get(key)
        if not isinstance(values, list):
            continue
        converted = [u for u in (_convert_url(item) for item in values) if u]
        if converted:
            return converted
    return []


def _normalize_location(value: object) -> dict | None:
    """Normalize op_model_item::ItemLocation.

    The enum has exactly one externally tagged variant, ``Gps``, whose value
    is ``{"id": <uuid>, "location": <optional coordinate>}``.
    """
    if not isinstance(value, dict):
        return None
    gps = value.get("Gps") if isinstance(value.get("Gps"), dict) else value
    if "id" not in gps and "location" not in gps:
        return None
    location = gps.get("location")
    if location is not None and not isinstance(location, dict):
        location = None
    return {
        "Gps": {
            "id": _text_value(gps.get("id")),
            "location": location,
        }
    }


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

    # The official exporter always writes these scalar fields.  ``subtitle``
    # and ``url`` are non-Option Strings in the importer model, so omission
    # fails with "missing field"; empty strings are the neutral value.
    result["url"] = str(source.get("url", "") or "")
    result["subtitle"] = str(source.get("subtitle") or source.get("ainfo") or "")
    if source.get("pgrng") is not None:
        result["pgrng"] = _as_bool(source["pgrng"])
    # ``icons`` and ``watchtowerExclusions`` are Option values; the official
    # exporter writes null when there is nothing to record.
    result["icons"] = None
    result["watchtowerExclusions"] = None

    converted_urls = _overview_urls(source)
    if converted_urls:
        result["urls"] = converted_urls
        if not result["url"]:
            # Local rows may omit the singular primary URL even though they
            # carry a website list.
            result["url"] = converted_urls[0]["url"]
    tags = source.get("tags")
    if isinstance(tags, list) and tags:
        result["tags"] = [str(tag) for tag in tags]
    if source.get("ps") is not None:
        parsed = _as_int(source["ps"])
        if parsed is not None and 0 <= parsed <= 255:
            result["ps"] = parsed
    if source.get("pbe") is not None:
        pbe = source["pbe"]
        parsed_pbe: float | None = None
        if isinstance(pbe, (int, float)) and not isinstance(pbe, bool):
            parsed_pbe = float(pbe)
        elif isinstance(pbe, str):
            try:
                parsed_pbe = float(pbe)
            except ValueError:
                parsed_pbe = None
        # Python's json.dumps writes NaN/Infinity by default, but serde_json
        # rejects them as invalid JSON.  Omit non-finite values.
        if parsed_pbe is not None and math.isfinite(parsed_pbe):
            result["pbe"] = parsed_pbe

    subtitle = result["subtitle"]
    if not subtitle and category_uuid in ("001", "005"):
        for field in details.get("loginFields", []):
            if field.get("designation") == "username":
                subtitle = field.get("value") or ""
                break
    result["subtitle"] = str(subtitle)

    # ``appIds`` exists only in the local B5 overview and is not accepted by
    # the v3 importer's ItemOverview field visitor.  ``passkey``/``passkeyId``
    # are accepted through force_none and discarded, so canonical profiles do
    # not emit them; only the raw ``full`` profile (which returns above) keeps
    # the local passkey overview.
    for key in ("b5UserUUID", "b5UserUuid"):
        if key not in source or source[key] in (None, [], {}):
            continue
        canonical_key = "b5UserUuid" if key == "b5UserUUID" else key
        result[canonical_key] = source[key]

    locations = source.get("locations")
    if isinstance(locations, list):
        cleaned_locations = [
            item for item in (_normalize_location(value) for value in locations) if item
        ]
        if cleaned_locations:
            result["locations"] = cleaned_locations

    exclusions = source.get("watchtowerExclusions")
    if isinstance(exclusions, dict) and exclusions:
        result["watchtowerExclusions"] = {
            key: _as_bool(exclusions.get(key, False)) for key in WATCHTOWER_KEYS
        }
    elif isinstance(exclusions, list) and exclusions:
        selected = {
            key for key in exclusions if isinstance(key, str) and key in WATCHTOWER_KEYS
        }
        if selected:
            result["watchtowerExclusions"] = {
                key: key in selected for key in WATCHTOWER_KEYS
            }

    # The v3 ItemShortcut is a struct, while older/local overviews may store
    # just the shortcut string.  Normalize both forms and drop unknown keys.
    shortcut = source.get("shortcut")
    if isinstance(shortcut, str) and shortcut:
        result["shortcut"] = {"value": shortcut}
    elif isinstance(shortcut, dict):
        value = (
            shortcut.get("value")
            or shortcut.get("key")
            or shortcut.get("shortcut")
            or shortcut.get("text")
        )
        if value:
            result["shortcut"] = {
                "value": str(value),
                "case_sensitive": _as_bool(shortcut.get("case_sensitive", False)),
            }

    # The exporter emits ``migrationDestination`` for items migrated from
    # another account.  The local B5 overview may use either spelling; keep
    # only the three fields the importer struct understands.
    migration = source.get("migrationDestination", source.get("MigrationDestination"))
    if isinstance(migration, dict):
        cleaned = {
            key: str(migration[key])
            for key in MIGRATION_KEYS
            if migration.get(key) is not None
        }
        if len(cleaned) == len(MIGRATION_KEYS):
            result["migrationDestination"] = cleaned
    return result



def _file_reference_id(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    inner = value.get("file") if isinstance(value.get("file"), dict) else value
    return str(inner.get("documentId") or inner.get("document_id") or "")


def _strip_missing_file_refs(
    details: dict, file_info: dict[str, tuple[str, bytes]]
) -> dict:
    """Full-profile equivalent of dropping unavailable file references."""
    result = copy.deepcopy(details)
    attrs = result.get("documentAttributes")
    if isinstance(attrs, dict):
        document_id = _file_reference_id(attrs)
        if document_id and document_id not in file_info:
            result.pop("documentAttributes", None)
    sections = result.get("sections")
    if isinstance(sections, list):
        for section in sections:
            if not isinstance(section, dict):
                continue
            fields = section.get("fields")
            if not isinstance(fields, list):
                continue
            kept = []
            for field in fields:
                if isinstance(field, dict):
                    document_id = _file_reference_id(
                        field.get("value", field.get("v"))
                    )
                    if document_id and document_id not in file_info:
                        continue
                kept.append(field)
            section["fields"] = kept
    return result


def _normalize_item(
    item: Item,
    document_size: int | None = None,
    profile: str = PROFILE_OFFICIAL,
    file_info: dict[str, tuple[str, bytes]] | None = None,
) -> dict:
    data = item.data
    category_uuid = str(data.get("category_uuid", ""))
    if profile == PROFILE_FULL and file_info is not None:
        details = _strip_missing_file_refs(item.details or {}, file_info)
    else:
        details = _normalize_details(
            item.details or {}, category_uuid, document_size, profile, file_info
        )
    if profile == PROFILE_FULL:
        overview = copy.deepcopy(item.overview or {})
    else:
        overview = _normalize_overview(item.overview or {}, details, category_uuid, profile)
    result = {
        "uuid": str(item.uuid),
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


def _normalize_vault(vault: Vault, profile: str = PROFILE_OFFICIAL) -> dict:
    attrs = dict(vault.attrs or {})
    name = attrs.get("name") or f"Vault {vault.uuid[:6]}"
    desc = attrs.get("desc", attrs.get("description", ""))
    avatar = attrs.get("avatar", attrs.get("icon", "") if isinstance(attrs.get("icon"), str) else "")
    vault_type = str(vault.type or "U")
    if profile != PROFILE_FULL:
        # The v3 importer turns a non-empty avatar into a ``files/<name>``
        # lookup.  The local database does not contain the avatar blobs we
        # would need to satisfy that lookup, so canonical profiles clear the
        # field instead of emitting a dangling file reference.
        avatar = ""
        if vault_type not in ("P", "E", "U"):
            vault_type = "U"
    return {
        "uuid": vault.uuid,
        "desc": str(desc or ""),
        "avatar": str(avatar or ""),
        "name": str(name),
        "type": vault_type,
    }


def _normalize_account(account: Account, profile: str = PROFILE_OFFICIAL) -> dict:
    data = account.data
    fallback = data.get("user_email") or account.uuid
    full_name = data.get("fullName") or data.get("full_name")
    avatar = data.get("team_avatar") or data.get("user_avatar") or ""
    if profile != PROFILE_FULL:
        # See _normalize_vault: account avatars are also resolved as files by
        # the importer.  The blob is not part of the local export cache.
        avatar = ""
    return {
        "accountName": str(
            data.get("team_name")
            or full_name
            or data.get("user_name")
            or fallback
        ),
        "name": str(
            full_name or data.get("user_name") or data.get("team_name") or fallback
        ),
        "avatar": str(avatar or ""),
        "email": str(data.get("user_email") or ""),
        "uuid": str(account.uuid),
        "domain": str(data.get("sign_in_url") or ""),
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
            # The official exporter does not export Trash.  `importer` keeps
            # deleted items because the importer schema accepts them; `full`
            # is a local backup and keeps everything.
            if (
                profile in (PROFILE_OFFICIAL, PROFILE_EXPORTER)
                and item_state(item.data.get("state")) == "deleted"
            ):
                continue

            file_info: dict[str, tuple[str, bytes]] = {}
            raw_details = item.details or {}
            if files_dir is not None:
                for reference in iter_file_references(raw_details):
                    document_id = str(
                        reference.get("documentId")
                        or reference.get("document_id")
                        or ""
                    )
                    if not document_id or document_id in file_info:
                        continue
                    try:
                        extracted = extract_file_reference(
                            reference, account.uuid, files_dir, fallback_key=vault.key
                        )
                    except (FileNotFoundError, DecryptionError, ValueError) as exc:
                        warnings.warn(f"item {item.uuid}: {exc}", stacklevel=2)
                        continue
                    if extracted is not None:
                        file_info[document_id] = extracted

            if (
                files_dir is not None
                and str(item.data.get("category_uuid", "")) == "006"
                and isinstance(raw_details.get("documentAttributes"), dict)
                and not file_info
            ):
                warnings.warn(
                    f"item {item.uuid}: document item has no locally "
                    "available file; exporting it without documentAttributes",
                    stacklevel=2,
                )

            normalized = _normalize_item(item, None, profile, file_info)
            items.append(normalized)
            for document_id, (file_name, content) in file_info.items():
                # The v3 exporter names file entries ``<documentId>__<fileName>``
                # (two underscores).  The importer reconstructs the same name
                # from documentAttributes before calling ZipArchive::by_name.
                files[f"files/{document_id}__{file_name}"] = content
        vaults.append({"attrs": _normalize_vault(vault, profile), "items": items})
    data = {
        "accounts": [
            {"attrs": _normalize_account(account, profile), "vaults": vaults}
        ]
    }
    validate_export_data(data, profile)
    return data, files


def _shape(value: object) -> dict:
    """Describe a JSON value without including any of its contents."""
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number", "finite": math.isfinite(value)}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        shapes: dict[str, dict] = {}
        for item in value:
            descriptor = _shape(item)
            shapes[json.dumps(descriptor, sort_keys=True)] = descriptor
        return {
            "type": "array",
            "length": len(value),
            "items": list(shapes.values()),
        }
    if isinstance(value, dict):
        return {
            "type": "object",
            "keys": {key: _shape(child) for key, child in value.items()},
        }
    return {"type": type(value).__name__}


def shape_report(data: dict) -> dict:
    """Return a value-free structural report for debugging deserialize errors."""
    return _shape(data)


def write_1pux(
    path: str | Path,
    account: Account,
    files_dir: Path | None = None,
    profile: str = PROFILE_OFFICIAL,
    shape_report_path: str | Path | None = None,
) -> tuple[Path, int, int]:
    """Write a 1PUX file using the selected schema profile."""
    path = Path(path)
    data, files = build_export_data(account, files_dir, profile)
    if shape_report_path is not None:
        report_path = Path(shape_report_path).expanduser()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(shape_report(data), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
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
            "attrs": _normalize_account(account, profile),
        },
        "vaults": [
            {
                "uuid": vault.uuid,
                "attrs": _normalize_vault(vault, profile),
                "items": [_normalize_item(item, profile=profile) for item in vault.items],
            }
            for vault in account.vaults
        ],
    }
