"""Strict schema for the official 1PUX v3 exporter/importer.

The field sets below were recovered from the desktop core's
``op_import_export::models::translation::onepux::v3`` structures.  The
serializer deliberately emits only the fields the official exporter emits;
the validator rejects fields outside this schema.
"""

from __future__ import annotations

from typing import Any

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
    "watchtowerExclusions",
    "appIds",
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
URL_KEYS = {"label", "url", "mode"}
LOGIN_FIELD_KEYS = {"value", "id", "name", "fieldType", "designation"}
HTML_FORM_KEYS = {"htmlMethod", "htmlAction", "htmlID", "htmlName"}
HISTORY_KEYS = {"value", "time"}

ACCOUNT_KEYS = {"accountName", "name", "avatar", "email", "uuid", "domain"}
VAULT_KEYS = {"uuid", "desc", "avatar", "name", "type"}
ATTRIBUTE_KEYS = {"version", "description", "timestamp"}


class SchemaError(ValueError):
    """Raised when an export does not match the official 1PUX v3 schema."""


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
        _keys(field, LOGIN_FIELD_KEYS, f"{where}.loginFields[{index}]", required={"value", "fieldType"})
        _require(isinstance(field["value"], str), f"{where}.loginFields[{index}].value must be a string")
        _require(field["fieldType"] in {"T", "E", "U", "N", "P", "A", "TEL"}, f"{where}: unsupported login fieldType")
        if "designation" in field:
            _require(
                field["designation"] in {"username", "password"},
                f"{where}: invalid login designation",
            )


def _validate_input_traits(traits: Any, where: str) -> None:
    _keys(traits, INPUT_TRAIT_KEYS, where)
    for key, value in traits.items():
        _require(isinstance(value, str), f"{where}.{key} must be a string")


def _validate_sections(sections: Any, where: str) -> None:
    _require(isinstance(sections, list), f"{where}: sections must be an array")
    for s_index, section in enumerate(sections):
        _keys(section, SECTION_KEYS, f"{where}.sections[{s_index}]", required={"fields"})
        fields = section["fields"]
        _require(isinstance(fields, list), f"{where}.sections[{s_index}].fields must be an array")
        for f_index, field in enumerate(fields):
            _keys(field, FIELD_KEYS, f"{where}.sections[{s_index}].fields[{f_index}]")
            if "value" in field:
                value = field["value"]
                _require(
                    isinstance(value, (str, int, float, bool, dict)),
                    f"{where}: invalid section field value",
                )
            if "inputTraits" in field:
                _validate_input_traits(
                    field["inputTraits"], f"{where}.sections[{s_index}].fields[{f_index}].inputTraits"
                )


def _validate_document_attributes(attrs: Any, where: str) -> None:
    _keys(attrs, DOCUMENT_KEYS, where, required={"fileName", "documentId"})
    _require(isinstance(attrs["fileName"], str), f"{where}.fileName must be a string")
    _require(isinstance(attrs["documentId"], str), f"{where}.documentId must be a string")
    if "decryptedSize" in attrs:
        _require(isinstance(attrs["decryptedSize"], int), f"{where}.decryptedSize must be an integer")


def _validate_details(details: Any, where: str) -> None:
    _keys(details, DETAILS_KEYS, where)
    if "loginFields" in details:
        _validate_login_fields(details["loginFields"], where)
    if "sections" in details:
        _validate_sections(details["sections"], where)
    if "documentAttributes" in details:
        _validate_document_attributes(details["documentAttributes"], f"{where}.documentAttributes")
    if "htmlForm" in details:
        _keys(details["htmlForm"], HTML_FORM_KEYS, f"{where}.htmlForm")
    if "passwordHistory" in details:
        _require(isinstance(details["passwordHistory"], list), f"{where}.passwordHistory must be an array")
        for index, entry in enumerate(details["passwordHistory"]):
            _keys(entry, HISTORY_KEYS, f"{where}.passwordHistory[{index}]", required={"value", "time"})
    if "passkey" in details:
        raise SchemaError(f"{where}: strict official export excludes passkeys")


def _validate_overview(overview: Any, where: str) -> None:
    _keys(overview, OVERVIEW_KEYS, where, required={"title"})
    _require(isinstance(overview["title"], str), f"{where}.title must be a string")
    if "urls" in overview:
        _require(isinstance(overview["urls"], list), f"{where}.urls must be an array")
        for index, url in enumerate(overview["urls"]):
            _keys(url, URL_KEYS, f"{where}.urls[{index}]", required={"url"})
    if "tags" in overview:
        _require(isinstance(overview["tags"], list), f"{where}.tags must be an array")
    if "passkey" in overview or "passkeyId" in overview:
        raise SchemaError(f"{where}: strict official export excludes passkeys")
    if "icons" in overview:
        _require(isinstance(overview["icons"], dict), f"{where}.icons must be an object")


def validate_export_data(data: dict) -> None:
    _keys(data, {"accounts"}, "export.data", required={"accounts"})
    _require(isinstance(data["accounts"], list), "export.data.accounts must be an array")
    for a_index, account in enumerate(data["accounts"]):
        where = f"export.data.accounts[{a_index}]"
        _keys(account, {"attrs", "vaults"}, where, required={"attrs", "vaults"})
        _keys(account["attrs"], ACCOUNT_KEYS, f"{where}.attrs", required=ACCOUNT_KEYS)
        _require(isinstance(account["vaults"], list), f"{where}.vaults must be an array")
        for v_index, vault in enumerate(account["vaults"]):
            v_where = f"{where}.vaults[{v_index}]"
            _keys(vault, {"attrs", "items"}, v_where, required={"attrs", "items"})
            _keys(vault["attrs"], VAULT_KEYS, f"{v_where}.attrs", required=VAULT_KEYS)
            _require(isinstance(vault["items"], list), f"{v_where}.items must be an array")
            for i_index, item in enumerate(vault["items"]):
                i_where = f"{v_where}.items[{i_index}]"
                _keys(item, ITEM_KEYS, i_where, required=ITEM_KEYS)
                _require(item["state"] in ITEM_STATES, f"{i_where}: invalid state")
                _require(isinstance(item["favIndex"], int), f"{i_where}.favIndex must be an integer")
                _require(isinstance(item["createdAt"], int), f"{i_where}.createdAt must be an integer")
                _require(isinstance(item["updatedAt"], int), f"{i_where}.updatedAt must be an integer")
                _require(isinstance(item["categoryUuid"], str), f"{i_where}.categoryUuid must be a string")
                _validate_details(item["details"], f"{i_where}.details")
                _validate_overview(item["overview"], f"{i_where}.overview")
