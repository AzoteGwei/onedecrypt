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
    "URLs",
    "tags",
    "ps",
    "pbe",
    "pgrng",
    "subtitle",
    "ainfo",
    "icons",
    "passkey",
    "passkeyId",
    "shortcut",
    "locations",
    "b5UserUUID",
    "b5UserUuid",
    "watchtowerExclusions",
    "migrationDestination",
    "MigrationDestination",
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
URL_KEYS = {"label", "url", "mode", "l", "u", "m"}
LOGIN_FIELD_KEYS = {"value", "id", "name", "fieldType", "type", "designation"}
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
INPUT_KEYBOARD_VALUES = {
    "default",
    "numberPad",
    "namePhonePad",
    "numbersAndPunctuation",
    "emailAddress",
    "uRL",
}
INPUT_CORRECTION_VALUES = {"default", "yes", "no"}
INPUT_CAPITALIZATION_VALUES = {"default", "none", "words", "sentences", "allCharacters"}
RSA_KEY_SIZE_VALUES = {"RsaUnsupported", "Rsa2048", "Rsa3072", "Rsa4096"}
CONTENT_TYPE_VALUES = {"Lexical", "Text"}
CONTENT_FORMAT_VALUES = {"FormattedText", "PlainText"}
ADDRESS_KEYS = {"street", "city", "country", "zip", "state"}
SSH_METADATA_KEYS = {"privateKey", "publicKey", "fingerprint", "keyType"}
FORMATTED_TEXT_KEYS = {
    "content",
    "content_type",
    "content_format",
    "format_version",
    "plain_text_display_value",
    "html_display_value",
}

ACCOUNT_KEYS = {
    "accountName",
    "name",
    "fullName",
    "avatar",
    "email",
    "uuid",
    "domain",
}
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
        for key in ("id", "name", "type"):
            if key in field:
                _require_string(field[key], f"{f_where}.{key}")
        if "designation" in field:
            _require(
                field["designation"] in {"username", "password"},
                f"{f_where}: invalid login designation",
            )


def _validate_input_traits(traits: Any, where: str) -> None:
    # DetailSectionFieldInputTraits has three non-Option fields.  The serde
    # visitor at 0x492fc80 returns ``missing field`` when any key is absent.
    _keys(traits, INPUT_TRAIT_KEYS, where, required=INPUT_TRAIT_KEYS)
    allowed = {
        "keyboard": INPUT_KEYBOARD_VALUES,
        "correction": INPUT_CORRECTION_VALUES,
        "capitalization": INPUT_CAPITALIZATION_VALUES,
    }
    for key, value in traits.items():
        _require_string(value, f"{where}.{key}")
        _require(
            value in allowed[key],
            f"{where}.{key}: invalid enum value {value!r}",
        )


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
    elif tag == "email":
        e_where = f"{where}.email"
        _keys(inner, {"email_address", "provider"}, e_where, required={"email_address", "provider"})
        _require_string(inner["email_address"], f"{e_where}.email_address")
        if inner["provider"] is not None:
            _require_string(inner["provider"], f"{e_where}.provider")
    elif tag == "address":
        a_where = f"{where}.address"
        _keys(inner, ADDRESS_KEYS, a_where, required=ADDRESS_KEYS)
        for key, child in inner.items():
            _require_string(child, f"{a_where}.{key}")
    elif tag == "sshKey":
        s_where = f"{where}.sshKey"
        _require(isinstance(inner, dict), f"{s_where} must be an object")
        _keys(inner, {"privateKey", "metadata"}, s_where, required={"privateKey"})
        _require_string(inner["privateKey"], f"{s_where}.privateKey")
        if "metadata" in inner:
            m_where = f"{s_where}.metadata"
            meta = inner["metadata"]
            _keys(meta, SSH_METADATA_KEYS, m_where, required=SSH_METADATA_KEYS)
            for key in ("privateKey", "publicKey", "fingerprint"):
                _require_string(meta[key], f"{m_where}.{key}")
            key_type = meta["keyType"]
            if isinstance(key_type, str):
                _require(
                    key_type == "ed25519",
                    f"{m_where}.keyType: expected 'ed25519' or an rsa object",
                )
            else:
                _keys(key_type, {"rsa"}, f"{m_where}.keyType", required={"rsa"})
                _require(
                    key_type["rsa"] in RSA_KEY_SIZE_VALUES,
                    f"{m_where}.keyType.rsa: invalid RSA key size",
                )
    elif tag == "ssoLogin":
        s_where = f"{where}.ssoLogin"
        _require(isinstance(inner, dict), f"{s_where} must be an object")
        _keys(inner, {"provider", "item"}, s_where, required={"provider"})
        _require_string(inner["provider"], f"{s_where}.provider")
        if "item" in inner:
            i_where = f"{s_where}.item"
            _keys(inner["item"], {"itemUuid", "vaultUuid"}, i_where, required={"itemUuid", "vaultUuid"})
            _require_string(inner["item"]["itemUuid"], f"{i_where}.itemUuid")
            _require_string(inner["item"]["vaultUuid"], f"{i_where}.vaultUuid")
    elif tag in SECTION_STRING_TAGS:
        _require_string(inner, f"{where}.{tag}")
    elif tag in ("date", "monthYear"):
        _require(
            inner is None or (isinstance(inner, int) and not isinstance(inner, bool)),
            f"{where}.{tag} must be an integer or null",
        )
    elif tag == "unsupported":
        _require(inner is None, f"{where}.unsupported must be null")
    elif tag == "reference":
        _require_string(inner, f"{where}.reference")
    elif tag == "formattedText":
        f_where = f"{where}.formattedText"
        _keys(inner, FORMATTED_TEXT_KEYS, f_where, required=FORMATTED_TEXT_KEYS)
        for key in ("content", "plain_text_display_value", "html_display_value"):
            _require_string(inner[key], f"{f_where}.{key}")
        _require(
            inner["content_type"] in CONTENT_TYPE_VALUES,
            f"{f_where}.content_type: invalid value",
        )
        _require(
            inner["content_format"] in CONTENT_FORMAT_VALUES,
            f"{f_where}.content_format: invalid value",
        )
        _require(
            isinstance(inner["format_version"], int)
            and not isinstance(inner["format_version"], bool),
            f"{f_where}.format_version must be an integer",
        )
    elif tag == "managedApplication":
        m_where = f"{where}.managedApplication"
        _keys(
            inner,
            {"applicationUuid", "loginInitiationUrl"},
            m_where,
            required={"applicationUuid", "loginInitiationUrl"},
        )
        for key, child in inner.items():
            _require_string(child, f"{m_where}.{key}")
    else:
        _require(
            isinstance(inner, (dict, str)),
            f"{where}.{tag} must be an object or string",
        )


def _validate_sections(sections: Any, where: str) -> None:
    _require(isinstance(sections, list), f"{where}: sections must be an array")
    for s_index, section in enumerate(sections):
        s_where = f"{where}.sections[{s_index}]"
        _keys(section, SECTION_KEYS, s_where, required={"title", "fields"})
        for key in ("title", "name"):
            if key in section:
                _require_string(section[key], f"{s_where}.{key}")
        if "hideAddAnotherField" in section:
            _require_bool(section["hideAddAnotherField"], f"{s_where}.hideAddAnotherField")
        fields = section["fields"]
        _require(isinstance(fields, list), f"{s_where}.fields must be an array")
        for f_index, field in enumerate(fields):
            f_where = f"{s_where}.fields[{f_index}]"
            _keys(
                field,
                FIELD_KEYS,
                f_where,
                required={
                    "title",
                    "id",
                    "value",
                    "guarded",
                    "multiline",
                    "dontGenerate",
                    "inputTraits",
                },
            )
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
    # DocumentAttributes requires fileName and decryptedSize; documentId is
    # Option<Uuid> in the serializer (0x4723be0) and may be absent.
    _keys(attrs, FULL_DOCUMENT_KEYS, where, required={"fileName", "decryptedSize"})
    _require(isinstance(attrs["fileName"], str), f"{where}.fileName must be a string")
    if "documentId" in attrs:
        _require(isinstance(attrs["documentId"], str), f"{where}.documentId must be a string")
    for key in ("decryptedSize", "encryptedSize", "unencryptedSize"):
        if key in attrs:
            _require(
                isinstance(attrs[key], int) and not isinstance(attrs[key], bool),
                f"{where}.{key} must be an integer",
            )
    for key in ("integrityHash", "nonce", "uti"):
        if key in attrs:
            _require_string(attrs[key], f"{where}.{key}")


def _validate_details(details: Any, where: str) -> None:
    _keys(
        details,
        DETAILS_KEYS,
        where,
        required={"loginFields", "sections", "passwordHistory"},
    )
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
        raise SchemaError(f"{where}: passkey is not part of this profile")


def _validate_overview(overview: Any, where: str) -> None:
    # ItemOverview.subtitle is a required String (missing-field call at
    # 0x4587208 with the literal "subtitle").  The canonical exporter also
    # always writes url/icons/watchtowerExclusions.
    _keys(
        overview,
        OVERVIEW_KEYS,
        where,
        required={"title", "subtitle", "url", "icons", "watchtowerExclusions"},
    )
    for key in ("title", "url", "subtitle", "ainfo", "b5UserUuid", "b5UserUUID"):
        if key in overview:
            _require_string(overview[key], f"{where}.{key}")
    if "urls" in overview:
        _require(isinstance(overview["urls"], list), f"{where}.urls must be an array")
        for index, url in enumerate(overview["urls"]):
            u_where = f"{where}.urls[{index}]"
            _keys(url, URL_KEYS, u_where, required={"url"})
            _require_string(url["url"], f"{u_where}.url")
            for key in ("label", "mode", "l", "m"):
                if key in url:
                    _require_string(url[key], f"{u_where}.{key}")
    if "URLs" in overview:
        _require(isinstance(overview["URLs"], list), f"{where}.URLs must be an array")
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
        _require(
            overview["icons"] is None or isinstance(overview["icons"], dict),
            f"{where}.icons must be null or an object",
        )
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
            l_where = f"{where}.locations[{index}]"
            _keys(location, {"Gps"}, l_where, required={"Gps"})
            _keys(
                location["Gps"],
                {"id", "location"},
                f"{l_where}.Gps",
                required={"id", "location"},
            )
            _require_string(location["Gps"]["id"], f"{l_where}.Gps.id")
            if location["Gps"]["location"] is not None:
                _require(
                    isinstance(location["Gps"]["location"], dict),
                    f"{l_where}.Gps.location must be null or an object",
                )
    for key in ("migrationDestination", "MigrationDestination"):
        if key in overview:
            m_key = key
            m_where = f"{where}.{m_key}"
            _keys(overview[m_key], MIGRATION_KEYS, m_where)
            for child_key, value in overview[m_key].items():
                _require_string(value, f"{m_where}.{child_key}")
    if "passkey" in overview or "passkeyId" in overview:
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
        _keys(
            account["attrs"],
            ACCOUNT_KEYS,
            f"{where}.attrs",
            required={"accountName", "name", "email", "domain"},
        )
        for key, value in account["attrs"].items():
            _require_string(value, f"{where}.attrs.{key}")
        _require(isinstance(account["vaults"], list), f"{where}.vaults must be an array")
        for v_index, vault in enumerate(account["vaults"]):
            v_where = f"{where}.vaults[{v_index}]"
            _keys(vault, {"attrs", "items"}, v_where, required={"attrs", "items"})
            _keys(
                vault["attrs"],
                VAULT_KEYS,
                f"{v_where}.attrs",
                required={"uuid", "name", "type"},
            )
            for key, value in vault["attrs"].items():
                _require_string(value, f"{v_where}.attrs.{key}")
            _require(isinstance(vault["items"], list), f"{v_where}.items must be an array")
            for i_index, item in enumerate(vault["items"]):
                i_where = f"{v_where}.items[{i_index}]"
                _keys(item, allowed_item_keys, i_where, required=ITEM_KEYS)
                _validate_item_basics(item, i_where)
                if not full:
                    # The importer's ItemDetails/ItemOverview visitors accept
                    # passkey fields only through force_none, which discards
                    # the payload.  They are therefore not part of any
                    # importable profile; only the raw full profile keeps them.
                    _validate_details(item["details"], f"{i_where}.details")
                    _validate_overview(item["overview"], f"{i_where}.overview")
