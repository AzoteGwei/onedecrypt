"""Schema profiles for the 1PUX v3 exporter/importer.

The field sets below were recovered from the desktop core's
``op_import_export::models::translation::onepux::v3`` structures.  They are
capability sets, not product-policy sets:

* ``official`` - intersection of the fields the official exporter emits and
  the official importer consumes.
* ``importer`` - fields the official importer consumes.
* ``exporter`` - fields the official exporter emits.
* ``full`` - all metadata available in the local database; this is a backup
  profile and is not guaranteed to be importable.

The current reverse-engineering matrix makes the first three field sets
identical; keeping distinct names makes later corrections explicit rather
than silently changing the meaning of a profile.
"""

from __future__ import annotations

import math
from typing import Any

PROFILE_OFFICIAL = "official"
PROFILE_IMPORTER = "importer"
PROFILE_EXPORTER = "exporter"
PROFILE_FULL = "full"
PROFILES = {PROFILE_OFFICIAL, PROFILE_IMPORTER, PROFILE_EXPORTER, PROFILE_FULL}

ITEM_STATES = {"active", "archived", "deleted"}

ITEM_KEYS = {
    "uuid",
    "favIndex",
    "createdAt",
    "updatedAt",
    "state",
    "categoryUuid",
    "details",
    "overview",
}
FULL_ITEM_KEYS = ITEM_KEYS | {"trashed", "changerUuid", "scope", "stateRaw", "validated"}

DETAILS_KEYS = {
    "loginFields",
    "notesPlain",
    "sections",
    "passwordHistory",
    "documentAttributes",
    "passkey",
    "password",
    "htmlForm",
}

OVERVIEW_KEYS = {
    "title",
    "url",
    "urls",
    "tags",
    "ps",
    "pbe",
    "pgrng",
    "subtitle",
    "icons",
    "passkey",
    "passkeyId",
    "shortcut",
    "locations",
    "b5UserUUID",
    "b5UserUuid",
    "watchtowerExclusions",
    "migrationDestination",
}

SECTION_KEYS = {"title", "name", "fields", "hideAddAnotherField"}
FIELD_KEYS = {
    "title",
    "id",
    "value",
    "guarded",
    "multiline",
    "dontGenerate",
    "indexAtSource",
    "placeholder",
    "inputTraits",
    "clipboardFilter",
}
INPUT_TRAIT_KEYS = {"keyboard", "correction", "capitalization"}
DOCUMENT_KEYS = {"fileName", "documentId", "decryptedSize"}
FULL_DOCUMENT_KEYS = {
    "fileName",
    "documentId",
    "decryptedSize",
    "encryptedSize",
    "unencryptedSize",
    "integrityHash",
    "nonce",
    "signingKey",
    "encryptionKey",
    "uti",
}
URL_KEYS = {"label", "url", "mode"}
LOGIN_FIELD_KEYS = {"value", "id", "name", "fieldType", "designation"}
HTML_FORM_KEYS = {"htmlMethod", "htmlAction", "htmlId", "htmlID", "htmlName"}
HISTORY_KEYS = {"value", "time"}
SHORTCUT_KEYS = {"value", "case_sensitive"}
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
MIGRATION_KEYS = {"itemUuid", "accountUuid", "vaultUuid"}
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
    "email",
    "gender",
    "menu",
    "phone",
    "string",
    "totp",
    "url",
}

ACCOUNT_KEYS = {"accountName", "name", "avatar", "email", "uuid", "domain"}
VAULT_KEYS = {"uuid", "desc", "avatar", "name", "type"}
ATTRIBUTE_KEYS = {"version", "description", "timestamp"}


class SchemaError(ValueError):
    """Raised when an export does not match the selected 1PUX profile."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SchemaError(message)


def _keys(value: dict, allowed: set[str], where: str, *, required: set[str] | None = None) -> None:
    _require(isinstance(value, dict), f"{where}: expected an object")
    extra = set(value) - allowed
    _require(not extra, f"{where}: unexpected field(s): {', '.join(sorted(extra))}")
    if required:
        missing = required - set(value)
        _require(not missing, f"{where}: missing field(s): {', '.join(sorted(missing))}")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_string(value: Any, where: str) -> None:
    _require(isinstance(value, str), f"{where} must be a string")


def _require_bool(value: Any, where: str) -> None:
    _require(isinstance(value, bool), f"{where} must be a boolean")


def _require_optional_string(value: Any, where: str) -> None:
    if value is not None:
        _require_string(value, where)


def validate_attributes(attributes: dict) -> None:
    _keys(attributes, ATTRIBUTE_KEYS, "export.attributes", required=ATTRIBUTE_KEYS)
    _require(attributes["version"] == 3, "export.attributes: version must be 3")
    _require(
        attributes["description"] == "1Password Unencrypted Export",
        "export.attributes: unexpected description",
    )
    _require(isinstance(attributes["timestamp"], int), "export.attributes: timestamp must be an integer")


def _validate_login_fields(fields: Any, where: str) -> None:
    _require(isinstance(fields, list), f"{where}: loginFields must be an array")
    for index, field in enumerate(fields):
        f_where = f"{where}.loginFields[{index}]"
        _keys(field, LOGIN_FIELD_KEYS, f_where, required={"value", "fieldType"})
        _require_string(field["value"], f"{f_where}.value")
        _require_string(field["fieldType"], f"{f_where}.fieldType")
        for key in ("id", "name"):
            if key in field:
                _require_string(field[key], f"{f_where}.{key}")
        if "designation" in field:
            _require(
                field["designation"] in {"username", "password"},
                f"{f_where}: invalid login designation",
            )


def _validate_input_traits(traits: Any, where: str) -> None:
    _keys(traits, INPUT_TRAIT_KEYS, where)
    for key, value in traits.items():
        _require_string(value, f"{where}.{key}")


def _validate_section_value(value: Any, where: str) -> None:
    _require(isinstance(value, dict), f"{where}: SectionFieldValue must be an object")
    tags = [key for key in value if key in SECTION_VALUE_TAGS]
    _require(
        len(tags) == 1 and len(value) == 1,
        f"{where}: SectionFieldValue must have exactly one type key",
    )
    tag = tags[0]
    inner = value[tag]
    if tag == "file":
        _validate_document_attributes(inner, f"{where}.file")
    elif tag in SECTION_STRING_TAGS:
        _require_string(inner, f"{where}.{tag}")
    elif tag in ("date", "monthYear"):
        _require(
            isinstance(inner, (int, str)) and not isinstance(inner, bool),
            f"{where}.{tag} must be an integer or string",
        )
    else:
        _require(
            isinstance(inner, (dict, str)),
            f"{where}.{tag} must be an object or string",
        )


def _validate_sections(sections: Any, where: str) -> None:
    _require(isinstance(sections, list), f"{where}: sections must be an array")
    for s_index, section in enumerate(sections):
        s_where = f"{where}.sections[{s_index}]"
        _keys(section, SECTION_KEYS, s_where, required={"fields"})
        for key in ("title", "name"):
            if key in section:
                _require_string(section[key], f"{s_where}.{key}")
        if "hideAddAnotherField" in section:
            _require_bool(section["hideAddAnotherField"], f"{s_where}.hideAddAnotherField")
        fields = section["fields"]
        _require(isinstance(fields, list), f"{s_where}.fields must be an array")
        for f_index, field in enumerate(fields):
            f_where = f"{s_where}.fields[{f_index}]"
            _keys(field, FIELD_KEYS, f_where)
            for key in ("title", "id"):
                if key in field:
                    _require_string(field[key], f"{f_where}.{key}")
            if "value" in field:
                _validate_section_value(field["value"], f"{f_where}.value")
            for key in ("guarded", "multiline", "dontGenerate"):
                if key in field:
                    _require_bool(field[key], f"{f_where}.{key}")
            if "indexAtSource" in field:
                _require(
                    isinstance(field["indexAtSource"], int)
                    and not isinstance(field["indexAtSource"], bool),
                    f"{f_where}.indexAtSource must be an integer",
                )
            for key in ("placeholder", "clipboardFilter"):
                if key in field:
                    _require_string(field[key], f"{f_where}.{key}")
            if "inputTraits" in field:
                _validate_input_traits(field["inputTraits"], f"{f_where}.inputTraits")


def _validate_document_attributes(attrs: Any, where: str) -> None:
    _keys(attrs, DOCUMENT_KEYS, where, required={"fileName", "documentId"})
    _require(isinstance(attrs["fileName"], str), f"{where}.fileName must be a string")
    _require(isinstance(attrs["documentId"], str), f"{where}.documentId must be a string")
    if "decryptedSize" in attrs:
        _require(isinstance(attrs["decryptedSize"], int), f"{where}.decryptedSize must be an integer")


def _validate_details(details: Any, where: str, *, allow_passkey: bool) -> None:
    _keys(details, DETAILS_KEYS, where)
    for key in ("notesPlain", "password"):
        if key in details:
            _require_string(details[key], f"{where}.{key}")
    if "loginFields" in details:
        _validate_login_fields(details["loginFields"], where)
    if "sections" in details:
        _validate_sections(details["sections"], where)
    if "documentAttributes" in details:
        _validate_document_attributes(details["documentAttributes"], f"{where}.documentAttributes")
    if "htmlForm" in details:
        form_where = f"{where}.htmlForm"
        _keys(details["htmlForm"], HTML_FORM_KEYS, form_where)
        for key, value in details["htmlForm"].items():
            _require_string(value, f"{form_where}.{key}")
    if "passwordHistory" in details:
        _require(isinstance(details["passwordHistory"], list), f"{where}.passwordHistory must be an array")
        for index, entry in enumerate(details["passwordHistory"]):
            entry_where = f"{where}.passwordHistory[{index}]"
            _keys(entry, HISTORY_KEYS, entry_where, required={"value", "time"})
            _require_string(entry["value"], f"{entry_where}.value")
            _require(
                isinstance(entry["time"], int) and not isinstance(entry["time"], bool),
                f"{entry_where}.time must be an integer",
            )
    if "passkey" in details:
        if not allow_passkey:
            raise SchemaError(f"{where}: passkey is not part of this profile")
        _require(isinstance(details["passkey"], dict), f"{where}.passkey must be an object")


def _validate_overview(overview: Any, where: str, *, allow_passkey: bool) -> None:
    _keys(overview, OVERVIEW_KEYS, where, required={"title"})
    for key in ("title", "url", "subtitle", "b5UserUUID", "b5UserUuid", "passkeyId"):
        if key in overview:
            _require_string(overview[key], f"{where}.{key}")
    if "urls" in overview:
        _require(isinstance(overview["urls"], list), f"{where}.urls must be an array")
        for index, url in enumerate(overview["urls"]):
            u_where = f"{where}.urls[{index}]"
            _keys(url, URL_KEYS, u_where, required={"url"})
            _require_string(url["url"], f"{u_where}.url")
            for key in ("label", "mode"):
                if key in url:
                    _require_string(url[key], f"{u_where}.{key}")
    if "tags" in overview:
        _require(isinstance(overview["tags"], list), f"{where}.tags must be an array")
        for index, tag in enumerate(overview["tags"]):
            _require_string(tag, f"{where}.tags[{index}]")
    if "ps" in overview:
        _require(
            isinstance(overview["ps"], int) and not isinstance(overview["ps"], bool),
            f"{where}.ps must be an integer",
        )
        _require(0 <= overview["ps"] <= 255, f"{where}.ps must fit in a u8")
    if "pbe" in overview:
        _require(_is_number(overview["pbe"]), f"{where}.pbe must be a number")
    if "pgrng" in overview:
        _require_bool(overview["pgrng"], f"{where}.pgrng")
    if "icons" in overview:
        _require(isinstance(overview["icons"], dict), f"{where}.icons must be an object")
    if "shortcut" in overview:
        s_where = f"{where}.shortcut"
        _keys(overview["shortcut"], SHORTCUT_KEYS, s_where, required={"value"})
        _require_string(overview["shortcut"]["value"], f"{s_where}.value")
        if "case_sensitive" in overview["shortcut"]:
            _require_bool(
                overview["shortcut"]["case_sensitive"], f"{s_where}.case_sensitive"
            )
    if "watchtowerExclusions" in overview:
        exclusions = overview["watchtowerExclusions"]
        if exclusions is not None:
            e_where = f"{where}.watchtowerExclusions"
            _keys(exclusions, WATCHTOWER_KEYS, e_where)
            for key, value in exclusions.items():
                _require_bool(value, f"{e_where}.{key}")
    if "locations" in overview:
        _require(isinstance(overview["locations"], list), f"{where}.locations must be an array")
        for index, location in enumerate(overview["locations"]):
            _require(
                isinstance(location, dict),
                f"{where}.locations[{index}] must be an object",
            )
    if "migrationDestination" in overview:
        m_where = f"{where}.migrationDestination"
        _keys(overview["migrationDestination"], MIGRATION_KEYS, m_where)
        for key, value in overview["migrationDestination"].items():
            _require_string(value, f"{m_where}.{key}")
    if ("passkey" in overview or "passkeyId" in overview) and not allow_passkey:
        raise SchemaError(f"{where}: passkey metadata is not part of this profile")


def _validate_item_basics(item: dict, where: str) -> None:
    _require_string(item["uuid"], f"{where}.uuid")
    _require(item["state"] in ITEM_STATES, f"{where}: invalid state")
    _require(
        isinstance(item["favIndex"], int) and not isinstance(item["favIndex"], bool),
        f"{where}.favIndex must be an integer",
    )
    _require(0 <= item["favIndex"] <= 0xFFFFFFFF, f"{where}.favIndex must fit in a u32")
    _require(
        isinstance(item["createdAt"], int) and not isinstance(item["createdAt"], bool),
        f"{where}.createdAt must be an integer",
    )
    _require(
        isinstance(item["updatedAt"], int) and not isinstance(item["updatedAt"], bool),
        f"{where}.updatedAt must be an integer",
    )
    _require_string(item["categoryUuid"], f"{where}.categoryUuid")
    _require(isinstance(item["details"], dict), f"{where}.details must be an object")
    _require(isinstance(item["overview"], dict), f"{where}.overview must be an object")


def _validate_finite(value: Any, where: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise SchemaError(f"{where}: non-finite float is not valid JSON")
    if isinstance(value, dict):
        for key, child in value.items():
            _validate_finite(child, f"{where}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_finite(child, f"{where}[{index}]")


def validate_export_data(data: dict, profile: str = PROFILE_OFFICIAL) -> None:
    if profile not in PROFILES:
        raise SchemaError(f"unknown schema profile {profile!r}")
    _validate_finite(data, "export.data")
    _keys(data, {"accounts"}, "export.data", required={"accounts"})
    _require(isinstance(data["accounts"], list), "export.data.accounts must be an array")
    full = profile == PROFILE_FULL
    allowed_item_keys = FULL_ITEM_KEYS if full else ITEM_KEYS
    for a_index, account in enumerate(data["accounts"]):
        where = f"export.data.accounts[{a_index}]"
        _keys(account, {"attrs", "vaults"}, where, required={"attrs", "vaults"})
        _keys(account["attrs"], ACCOUNT_KEYS, f"{where}.attrs", required=ACCOUNT_KEYS)
        for key, value in account["attrs"].items():
            _require_string(value, f"{where}.attrs.{key}")
        _require(isinstance(account["vaults"], list), f"{where}.vaults must be an array")
        for v_index, vault in enumerate(account["vaults"]):
            v_where = f"{where}.vaults[{v_index}]"
            _keys(vault, {"attrs", "items"}, v_where, required={"attrs", "items"})
            _keys(vault["attrs"], VAULT_KEYS, f"{v_where}.attrs", required=VAULT_KEYS)
            for key, value in vault["attrs"].items():
                _require_string(value, f"{v_where}.attrs.{key}")
            _require(isinstance(vault["items"], list), f"{v_where}.items must be an array")
            for i_index, item in enumerate(vault["items"]):
                i_where = f"{v_where}.items[{i_index}]"
                _keys(item, allowed_item_keys, i_where, required=ITEM_KEYS)
                _validate_item_basics(item, i_where)
                if not full:
                    allow_passkey = profile == PROFILE_IMPORTER
                    _validate_details(item["details"], f"{i_where}.details", allow_passkey=allow_passkey)
                    _validate_overview(item["overview"], f"{i_where}.overview", allow_passkey=allow_passkey)
