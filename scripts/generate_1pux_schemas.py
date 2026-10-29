#!/usr/bin/env python3
"""Generate the four annotated 1PUX JSON Schemas.

The schemas document the JSON payloads stored in ``export.data`` and
``export.attributes`` inside a 1PUX ZIP archive.  They are generated from one
declarative model so the four profiles cannot drift accidentally:

``official``
    Fields the official exporter emits *and* the official importer consumes.
    This is the default/round-trip profile.

``importer``
    Every field the official importer's serde visitors accept, including the
    importer-only ``passkey`` field and legacy aliases.

``exporter``
    Fields the official exporter emits.  In the current reverse-engineering
    matrix this is the same field set as ``official`` because the exporter
    never emits passkeys and the importer accepts the same canonical fields.

``full``
    Every piece of metadata available in the local database.  This profile is
    a backup format, not a claim of official-import compatibility.

Run from the repository root::

    uv run python scripts/generate_1pux_schemas.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "schema"

PROFILES = ("official", "importer", "exporter", "full")

UUID_DESCRIPTION = (
    "1Password object identifier. The official exporter writes the usual "
    "26-character lowercase base32 identifier; the importer treats it as an "
    "opaque string, so this schema does not impose a pattern."
)
TIMESTAMP_DESCRIPTION = "Unix timestamp in seconds."


def text(description: str, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string", "description": description}
    result.update(extra)
    return result


def integer(description: str, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "integer", "description": description}
    result.update(extra)
    return result


def number(description: str, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "number", "description": description}
    result.update(extra)
    return result


def boolean(description: str, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "boolean", "description": description}
    result.update(extra)
    return result


def array(items: dict[str, Any], description: str, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "array",
        "description": description,
        "items": items,
    }
    result.update(extra)
    return result


def ref(name: str, description: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"$ref": f"#/$defs/{name}"}
    if description:
        result["description"] = description
    return result


def obj(
    description: str,
    properties: dict[str, Any],
    *,
    required: tuple[str, ...] = (),
    additional: bool = False,
    comment: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "object",
        "description": description,
        "properties": properties,
        "additionalProperties": additional,
    }
    if required:
        result["required"] = list(required)
    if comment:
        result["$comment"] = comment
    return result


def any_value(description: str) -> dict[str, Any]:
    return {
        "description": description,
        "type": ["object", "array", "string", "number", "boolean", "null"],
    }


def alias_field(description: str, alias: str) -> dict[str, Any]:
    return {
        **text(description),
        "$comment": f"Legacy/importer alias: ``{alias}`` is accepted as the same field.",
    }


# ---------------------------------------------------------------------------
# Shared object shapes
# ---------------------------------------------------------------------------


def export_attributes(profile: str) -> dict[str, Any]:
    properties = {
        "version": {
            **integer("1PUX schema version. The v3 exporter writes 3."),
            "const": 3,
        },
        "description": {
            **text("Human-readable format description."),
            "const": "1Password Unencrypted Export",
        },
        "timestamp": integer(
            "Export creation time. Recovered from the v3 exporter, which writes "
            "``timestamp`` rather than the ``createdAt`` spelling used by the "
            "public format documentation."
        ),
    }
    required = (
        ("version", "description", "timestamp")
        if profile in ("official", "exporter")
        else ()
    )
    return obj(
        "Contents of the ``export.attributes`` ZIP entry. This object is not "
        "part of ``export.data``; it is documented here because both files "
        "belong to the same 1PUX archive.",
        properties,
        required=required,
        additional=profile in ("importer", "full"),
        comment=(
            "Recovered from op_import_export::models::translation::onepux::v3. "
            "The public 1PUX page shows createdAt, while the shipped exporter "
            "writes timestamp. No createdAt property is declared here because "
            "the importer's acceptance of that spelling was not proven from "
            "the binary."
        ),
    )


def account_attrs(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "accountName": text(
            "Display name of the account/team as shown by the official exporter."
        ),
        "name": text("Account owner or team name."),
        "avatar": text(
            "Filename of the account avatar inside the ZIP ``files/`` "
            "directory. An empty string means no avatar. onedecrypt clears "
            "this field in canonical profiles because it does not export "
            "the avatar blob."
        ),
        "email": text("Account email address.", format="email"),
        "uuid": text(UUID_DESCRIPTION),
        "domain": text(
            "Account sign-in URL, for example https://my.1password.com/.",
            format="uri-reference",
        ),
    }
    if profile in ("importer", "full"):
        properties["fullName"] = alias_field(
            "Importer alias for the account display name.", "fullName"
        )
    return obj(
        "Account-level attributes stored under ``accounts[].attrs``.",
        properties,
        # The exporter writes avatar/uuid through Option fields and can skip
        # them when absent; keep them optional in the canonical schemas.
        required=(
            ("accountName", "name", "email", "domain")
            if profile in ("official", "exporter")
            else ()
        ),
        # The v2 AccountAttrs visitor rejects unknown fields.
        additional=profile == "full",
    )


def vault_attrs(profile: str) -> dict[str, Any]:
    vault_type: dict[str, Any] = text(
        "Vault type. P = Personal/Private, E = Everyone/Shared, U = "
        "user-created vault. The exporter can also emit T (team), S "
        "(shared), G (guest), M (managed) and D (default). onedecrypt "
        "canonical profiles map values outside P/E/U to U."
    )
    if profile in ("official", "exporter"):
        vault_type["enum"] = [
            "P",
            "E",
            "T",
            "U",
            "S",
            "G",
            "M",
            "D",
            "Unsupported",
        ]
    elif profile == "importer":
        # The importer maps known single-character values and falls back to
        # Unsupported for anything else, so it accepts an arbitrary string.
        vault_type["description"] = (
            "Vault type string. Known values are P/E/T/U/S/G/M/D; the "
            "importer falls back to Unsupported for other values."
        )
    return obj(
        "Vault-level attributes stored under ``vaults[].attrs``.",
        {
            "uuid": text(UUID_DESCRIPTION),
            "desc": text("Vault description; empty string when not set."),
            "avatar": text(
                "Filename of the vault avatar inside the ZIP ``files/`` "
                "directory. An empty string means no avatar. onedecrypt clears "
                "this field in canonical profiles because it does not export "
                "the avatar blob."
            ),
            "name": text("Vault name."),
            "type": vault_type,
        },
        # Vault uuid/avatar are Option fields in the exporter's attrs model.
        required=(
            ("desc", "name", "type")
            if profile in ("official", "exporter")
            else ()
        ),
        # The v2 VaultAttrs visitor rejects unknown fields.
        additional=profile == "full",
    )


def login_field(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "value": text("Field value."),
        "id": text("Field identifier; may be empty for template-driven fields."),
        "name": text("HTML form field name; may be empty."),
        "fieldType": text(
            "Free-form HTML input type. The official importer does not "
            "constrain this to the T/E/U/N/P/A/TEL list shown in older "
            "documentation; real vaults contain other values such as D or C.",
            examples=["T", "P", "D", "C"],
        ),
        "designation": {
            "type": "string",
            "description": (
                "Semantic role of a login field. At most one field should be "
                "``username`` and at most one ``password``."
            ),
            "enum": ["username", "password"],
        },
    }
    if profile in ("importer", "full"):
        properties["type"] = alias_field(
            "Legacy alias for ``fieldType`` accepted by the importer.", "type"
        )
    return obj(
        "A web-form/login field. The official exporter writes ``value``, "
        "``id``, ``name`` and ``fieldType``; ``designation`` is optional.",
        properties,
        required=("value", "fieldType") if profile in ("official", "exporter") else (),
        # The v2 LoginField visitor rejects unknown fields.
        additional=profile == "full",
        comment=(
            "ItemDetails.loginFields is Vec<LoginField>. The importer's "
            "visit_str accepts value/id/name/fieldType/type/designation."
        ),
    )


def password_history_entry(profile: str) -> dict[str, Any]:
    return obj(
        "One previous password. Entries are ordered oldest first; ``time`` is "
        "the moment that value stopped being current.",
        {
            "value": text("Previous password value."),
            "time": integer(TIMESTAMP_DESCRIPTION),
        },
        required=("value", "time"),
        additional=profile == "full",
    )


def html_form(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "htmlMethod": text("HTML form method, for example POST."),
        "htmlAction": text("HTML form action URL or path."),
        "htmlId": text(
            "HTML form id attribute. The shipped exporter writes ``htmlId`` "
            "(lower-case d)."
        ),
        "htmlName": text("HTML form name attribute."),
    }
    if profile in ("importer", "full"):
        properties["htmlID"] = alias_field(
            "Importer alias for ``htmlId``; accepted by the field visitor.",
            "htmlID",
        )
    return obj(
        "Saved web-form metadata (``details.htmlForm``). The official exporter "
        "emits ``htmlId``; the importer accepts both ``htmlId`` and "
        "``htmlID``.",
        properties,
        # The v2 DetailHTMLForm visitor rejects unknown fields.
        additional=profile == "full",
    )


def document_attributes(profile: str) -> dict[str, Any]:
    canonical = {
        "fileName": text(
            "Original file name. The ZIP entry is "
            "``files/<documentId>__<fileName>`` (two underscores)."
        ),
        "documentId": text(
            "Document identifier. Together with fileName it forms the ZIP "
            "entry name."
        ),
        "decryptedSize": integer(
            "Plaintext size in bytes.", minimum=0
        ),
    }
    if profile == "importer":
        canonical.update(
            {
                "encryptedSize": integer(
                    "Ciphertext size in bytes. Accepted by the importer for "
                    "legacy/v2 files; the canonical exporter omits it.",
                    minimum=0,
                ),
                "unencryptedSize": integer(
                    "Importer alias for ``decryptedSize``.", minimum=0
                ),
                "integrityHash": text(
                    "Base64 integrity hash accepted by the importer for "
                    "legacy/v2 files."
                ),
                "nonce": text(
                    "Base64 AES-GCM nonce accepted by the importer for "
                    "legacy/v2 files."
                ),
                "signingKey": any_value(
                    "Document signing key/JWK accepted by the importer for "
                    "legacy/v2 files."
                ),
                "encryptionKey": any_value(
                    "Document encryption key/JWK accepted by the importer for "
                    "legacy/v2 files."
                ),
                "uti": text(
                    "Uniform Type Identifier accepted by the importer for "
                    "legacy/v2 files."
                ),
            }
        )
    if profile == "full":
        canonical.update(
            {
                "encryptedSize": integer(
                    "Ciphertext size in bytes, preserved from the local "
                    "database.",
                    minimum=0,
                ),
                "unencryptedSize": integer(
                    "Plaintext size in bytes, preserved from the local database.",
                    minimum=0,
                ),
                "integrityHash": text("Raw integrity hash from the local database."),
                "nonce": text("Raw AES-GCM nonce from the local database."),
                "signingKey": any_value("Raw document signing key/JWK."),
                "encryptionKey": any_value("Raw document encryption key/JWK."),
                "uti": text("Raw Uniform Type Identifier."),
            }
        )
    return obj(
        "A document reference. Document items carry this object at "
        "``details.documentAttributes``; section attachments carry it at "
        "``details.sections[].fields[].value.file``.",
        canonical,
        required=(
            ("fileName", "documentId")
            if profile in ("official", "exporter")
            else ()
        ),
        # The v2 DocumentAttributes visitor rejects unknown fields.
        additional=profile == "full",
        comment=(
            "DocumentAttributes deserializer fields: fileName, documentId, "
            "signingKey, decryptedSize/unencryptedSize, encryptedSize, "
            "integrityHash, encryptionKey, nonce, uti."
        ),
    )


def overview_url(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "label": text("Display label for the URL; empty string when unlabeled."),
        "url": text("URL value.", format="uri-reference"),
        "mode": text(
            "1Password URL matching mode, for example anywhereOnWebsite or exact.",
            examples=["anywhereOnWebsite", "exact", "never"],
        ),
    }
    if profile in ("importer", "full"):
        properties["l"] = alias_field(
            "Legacy alias for ``label`` accepted by the importer.", "l"
        )
        properties["u"] = alias_field(
            "Legacy alias for ``url`` accepted by the importer.", "u"
        )
        properties["m"] = alias_field(
            "Legacy alias for ``mode`` accepted by the importer.", "m"
        )
    return obj(
        "One entry of ``overview.urls``. The canonical spelling uses "
        "``label``/``url``/``mode``.",
        properties,
        required=("url",) if profile in ("official", "exporter") else (),
        # The v2 OverviewUrl visitor rejects unknown fields.
        additional=profile == "full",
    )


def input_traits(profile: str) -> dict[str, Any]:
    return obj(
        "Keyboard/autocorrection hints for a section field "
        "(``details.sections[].fields[].inputTraits``). Values are template "
        "strings, not booleans; the importer accepts free-form strings.",
        {
            "keyboard": text("Keyboard type hint, e.g. default or numberPad."),
            "correction": text("Autocorrection hint, e.g. default or no."),
            "capitalization": text(
                "Autocapitalization hint, e.g. default or sentences."
            ),
        },
        # The v2 InputTraits visitor rejects unknown fields.
        additional=profile == "full",
    )


def section_field_value(profile: str) -> dict[str, Any]:
    """Return the externally-tagged SectionFieldValue enum schema."""

    def variant(
        key: str,
        description: str,
        value_schema: dict[str, Any],
    ) -> dict[str, Any]:
        return obj(
            description,
            {key: value_schema},
            required=(key,),
            additional=False,
            comment=(
                "SectionFieldValue is an externally tagged enum: the JSON "
                "object has exactly one key, which selects the field type."
            ),
        )

    variants: list[dict[str, Any]] = [
        variant(
            "address",
            "Postal address value.",
            obj(
                "Address object emitted by the official exporter.",
                {
                    "city": text("City."),
                    "country": text("Country."),
                    "state": text("State or province."),
                    "street": text("Street address."),
                    "zip": text("Postal/ZIP code."),
                },
                required=("city", "country", "state", "street", "zip"),
            ),
        ),
        variant("concealed", "Concealed/secret text.", text("Concealed value.")),
        variant(
            "creditCardNumber",
            "Credit-card number as text (the UI may store spaces or notes).",
            text("Credit-card number."),
        ),
        variant(
            "creditCardType",
            "Credit-card brand/type as text.",
            text("Credit-card type."),
        ),
        variant(
            "date",
            "Date value. The official exporter emits an integer or null.",
            {"type": ["integer", "null"], "description": "Date value."},
        ),
        variant(
            "email",
            "Email address with an optional provider label.",
            obj(
                "Email object emitted by the official exporter.",
                {
                    "email_address": text("Email address.", format="email"),
                    "provider": {
                        "type": ["string", "null"],
                        "description": "Optional email provider label.",
                    },
                },
                required=("email_address",),
            ),
        ),
        variant(
            "file",
            "Attachment reference. The importer reads the same DocumentAttributes "
            "shape used by document items, then loads "
            "``files/<documentId>__<fileName>`` from the archive.",
            ref("DocumentAttributes"),
        ),
        variant(
            "formattedText",
            "Formatted text value.",
            any_value("Formatted text object or string."),
        ),
        variant("gender", "Gender value.", text("Gender value.")),
        variant("menu", "Menu selection.", text("Menu value.")),
        variant(
            "managedApplication",
            "Managed-application credential value.",
            any_value("Managed application value."),
        ),
        variant(
            "monthYear",
            "Month/year value. The official exporter emits an integer or null.",
            {"type": ["integer", "null"], "description": "Month/year value."},
        ),
        variant("phone", "Phone number.", text("Phone number.")),
        variant(
            "reference",
            "Reference to another item/field.",
            any_value("Reference object or string."),
        ),
        variant(
            "sshKey",
            "SSH key value.",
            obj(
                "SSH key object emitted by the official exporter.",
                {
                    "privateKey": text("Private key material."),
                    "metadata": obj(
                        "SSH key metadata.",
                        {
                            "fingerprint": text("Key fingerprint."),
                            "keyType": {
                                "description": "Key type string or an object such as {\"rsa\": \"...\"}.",
                                "type": ["object", "string"],
                                "additionalProperties": True,
                            },
                            "privateKey": text("Private key material."),
                            "publicKey": text("Public key material."),
                        },
                        additional=True,
                    ),
                },
                additional=True,
            ),
        ),
        variant(
            "ssoLogin",
            "SSO login value.",
            obj(
                "SSO login object emitted by the official exporter.",
                {
                    "provider": text("SSO provider identifier."),
                    "item": obj(
                        "Optional linked item.",
                        {
                            "itemUuid": text("Linked item UUID."),
                            "vaultUuid": text("Linked vault UUID."),
                        },
                        additional=True,
                    ),
                },
                required=("provider",),
                additional=True,
            ),
        ),
        variant("string", "Plain string value.", text("String value.")),
        variant("totp", "One-time-password secret/URI.", text("TOTP value.")),
        variant(
            "unsupported",
            "Unit variant used by the importer for a value it could not classify.",
            {"type": "null", "description": "The unsupported variant carries no payload."},
        ),
        variant("url", "URL value.", text("URL value.", format="uri-reference")),
    ]
    if profile == "full":
        # The full profile keeps raw B5 section values, which can be scalars or
        # arbitrary objects in addition to the tagged enum shapes.
        return any_value(
            "Raw local section-field value. The full profile preserves the "
            "database representation, so it may be a tagged enum object, a "
            "scalar, or a vendor-specific object."
        )
    return {
        "description": (
            "Section field value. The v3 1PUX schema uses an externally tagged "
            "enum object with exactly one type key. The full profile preserves "
            "raw local values instead."
        ),
        "oneOf": variants,
    }


def detail_section_field(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "title": text("User-visible field label."),
        "id": text(
            "Field identifier. Uniqueness is not guaranteed; template fields "
            "use template-provided identifiers."
        ),
        "value": ref("SectionFieldValue"),
        "guarded": boolean("Whether the field is guarded/concealed."),
        "multiline": boolean("Whether the field is multiline."),
        "dontGenerate": boolean("Whether the password generator is disabled."),
        "indexAtSource": integer(
            "Original index of the field in its source form/section.",
            minimum=0,
        ),
        "placeholder": text("Placeholder text."),
        "inputTraits": ref("InputTraits"),
        "clipboardFilter": text("Clipboard filter hint."),
    }
    return obj(
        "One field inside a detail section. The official exporter emits "
        "long-form keys (title/id/value/...); short B5 keys are not part of "
        "the canonical profiles.",
        properties,
        required=("title", "id") if profile in ("official", "exporter") else (),
        # The v2 DetailSectionField visitor rejects unknown fields.
        additional=profile == "full",
        comment=(
            "DetailSectionField importer fields: title, id, value, "
            "indexAtSource, guarded, multiline, clipboardFilter, dontGenerate, "
            "inputTraits, placeholder. keyboard/correction live inside "
            "inputTraits, not at the field level."
        ),
    )


def detail_section(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "title": text("Section heading shown to the user."),
        "name": text("Stable section identifier within the item."),
        "fields": array(
            ref("DetailSectionField"),
            "Fields in this section. The official exporter always writes an "
            "array, possibly empty.",
        ),
        "hideAddAnotherField": boolean(
            "Whether the UI should hide the 'add another field' affordance."
        ),
    }
    return obj(
        "One group of item fields (``details.sections[]``).",
        properties,
        required=("fields",) if profile in ("official", "exporter") else (),
        # The v2 DetailSection visitor rejects unknown fields.
        additional=profile == "full",
        comment=(
            "DetailSection importer fields: title, name, fields, "
            "hideAddAnotherField."
        ),
    )


def passkey_value(profile: str) -> dict[str, Any]:
    return any_value(
        "Opaque passkey payload. The official 1PUX exporter does not emit "
        "passkeys; the importer model has a passkey field, so the importer "
        "and full profiles preserve the local value verbatim."
    )


def item_details(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "loginFields": array(
            ref("LoginField"), "Saved web-form/login fields."
        ),
        "notesPlain": text("Free-form notes; markdown formatting is preserved."),
        "sections": array(
            ref("DetailSection"), "Custom/structured item sections."
        ),
        "passwordHistory": array(
            ref("PasswordHistoryEntry"),
            "Previous passwords, ordered oldest first.",
        ),
        "documentAttributes": ref(
            "DocumentAttributes",
            "Document reference for Document items (categoryUuid 006).",
        ),
        "password": text(
            "Password value for Password items (categoryUuid 005), which have "
            "no loginFields."
        ),
        "htmlForm": ref("DetailHtmlForm"),
    }
    if profile in ("importer", "full"):
        properties["passkey"] = ref("Passkey")
    return obj(
        "Item details (``items[].details``). Every field is optional; a "
        "Document item typically has only documentAttributes, and a Password "
        "item typically has only password.",
        properties,
        # The v2 ItemDetails visitor rejects unknown fields.
        additional=profile == "full",
        comment=(
            "ItemDetails is the v2 struct reused by v3. The importer field "
            "visitor accepts htmlForm, loginFields, notesPlain, sections, "
            "passwordHistory, password, passkey and documentAttributes."
        ),
    )


def icon_key(profile: str) -> dict[str, Any]:
    return {
        "description": (
            "Opaque icon reference. The official exporter can emit custom "
            "icon metadata and write the referenced file under ``files/``. "
            "onedecrypt omits custom icons because their blobs are not part "
            "of the local export cache."
        ),
        "type": ["object", "string"],
        "additionalProperties": True,
    }


def watchtower_exclusions(profile: str) -> dict[str, Any]:
    checks = [
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
    ]
    return obj(
        "Watchtower exclusions object. The exporter writes null instead of "
        "this object when there are no exclusions; each boolean field selects "
        "one Watchtower check.",
        {name: boolean(f"Whether the {name} Watchtower check is excluded.") for name in checks},
        required=tuple(checks) if profile in ("official", "exporter") else (),
        # The importer's WatchtowerExclusions visitor ignores unknown fields;
        # the exporter only writes the twelve known boolean flags.
        additional=profile in ("importer", "full"),
    )


def item_shortcut(profile: str) -> dict[str, Any]:
    return obj(
        "Keyboard shortcut associated with the item. The exporter models "
        "this as a struct with ``value`` and ``case_sensitive`` rather than "
        "a bare string.",
        {
            "value": text("Shortcut key/value."),
            "case_sensitive": boolean("Whether the shortcut is case-sensitive."),
        },
        required=("value",) if profile in ("official", "exporter") else (),
        additional=profile in ("importer", "full"),
    )


def migration_destination(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "itemUuid": text("Destination item UUID."),
        "accountUuid": text("Destination account UUID."),
        "vaultUuid": text("Destination vault UUID."),
    }
    if profile in ("importer", "full"):
        properties["itemUUID"] = alias_field(
            "Importer alias for ``itemUuid``.", "itemUUID"
        )
        properties["accountUUID"] = alias_field(
            "Importer alias for ``accountUuid``.", "accountUUID"
        )
        properties["vaultUUID"] = alias_field(
            "Importer alias for ``vaultUuid``.", "vaultUUID"
        )
    return obj(
        "Migration destination emitted by the exporter for items that were "
        "migrated from another account.",
        properties,
        required=(
            ("itemUuid", "accountUuid", "vaultUuid")
            if profile in ("official", "exporter")
            else ()
        ),
        # The importer's MigrationDestination visitor rejects unknown fields.
        additional=profile == "full",
    )


def item_overview(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "title": text("Item title shown in the item list."),
        "url": text("Primary URL, if any.", format="uri-reference"),
        "urls": array(ref("OverviewUrl"), "All URLs associated with the item."),
        "tags": array(text("Tag value."), "Item tags."),
        "ps": integer(
            "Password strength score emitted by 1Password. The UI normally "
            "shows 0-100; the field is not range-checked by the importer."
        ),
        "pbe": number("Password breach/entropy estimate emitted by 1Password."),
        "pgrng": boolean("Password generator range/flag emitted by 1Password."),
        "subtitle": text(
            "Generated subtitle, usually the username or a short summary."
        ),
        "icons": {
            "description": (
                "Custom icon map keyed by icon slot, or null when the item has "
                "no custom icon. The exporter writes referenced files under "
                "``files/``; onedecrypt omits custom icon blobs."
            ),
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": ref("IconKey"),
                },
            ],
        },
        "shortcut": ref("ItemShortcut"),
        "locations": array(
            any_value("Location object."),
            "Locations associated with the item.",
        ),
        "b5UserUuid": text(
            "B5 user UUID. The official importer accepts both this spelling "
            "and ``b5UserUUID``."
        ),
        "b5UserUUID": text(
            "Alias spelling of ``b5UserUuid`` accepted by the official importer."
        ),
        "watchtowerExclusions": {
            "description": (
                "Watchtower exclusions. The exporter writes null when there "
                "are none, otherwise an object of boolean exclusion flags."
            ),
            "oneOf": [
                {"type": "null"},
                ref("WatchtowerExclusions"),
            ],
        },
        "migrationDestination": ref(
            "MigrationDestination",
            "Migration destination emitted by the official exporter.",
        ),
    }
    if profile in ("importer", "full"):
        properties["passkey"] = ref("Passkey")
        properties["passkeyId"] = text("Passkey identifier.")
        properties["MigrationDestination"] = alias_field(
            "Importer alias for ``migrationDestination``.", "MigrationDestination"
        )
        properties["ainfo"] = alias_field(
            "Legacy alias for ``subtitle`` accepted by the importer.", "ainfo"
        )
        properties["URLs"] = alias_field(
            "Legacy alias for ``urls`` accepted by the importer.", "URLs"
        )
    if profile == "full":
        properties["appIds"] = array(
            text("Application identifier."),
            "Local B5 app identifiers. Not accepted by the official importer, "
            "so this key exists only in the full profile.",
        )
    return obj(
        "Item overview (``items[].overview``). The official exporter emits "
        "the canonical keys; the importer additionally accepts several "
        "legacy spellings.",
        properties,
        required=("title",) if profile in ("official", "exporter") else (),
        # The v2 ItemOverview visitor rejects unknown fields.
        additional=profile == "full",
        comment=(
            "ItemOverview importer field list: ainfo, subtitle, b5UserUUID, "
            "b5UserUuid, icons, URLs, urls, tags, title, url, ps, pbe, pgrng, "
            "passkeyId, passkey, MigrationDestination, migrationDestination, "
            "watchtowerExclusions, shortcut, locations. appIds is local-only."
        ),
    )


def item(profile: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "uuid": text(UUID_DESCRIPTION),
        "favIndex": integer(
            "0 means not a favorite; greater than 0 means favorite.", minimum=0
        ),
        "createdAt": integer(TIMESTAMP_DESCRIPTION),
        "updatedAt": integer(TIMESTAMP_DESCRIPTION),
        "state": {
            "type": "string",
            "description": (
                "Item state. The v3 serializer maps 0, 1, 2 to active, "
                "archived and deleted; the importer accepts all three. "
                "onedecrypt's official/exporter policy skips trashed items "
                "during extraction, so those profiles normally contain only "
                "active/archived even though the format can represent deleted."
            ),
            "enum": ["active", "archived", "deleted"],
        },
        "categoryUuid": text(
            "Item category identifier. Known values include 001 Login, 002 "
            "Credit Card, 003 Secure Note, 004 Identity, 005 Password, 006 "
            "Document, 100 Software License, 114 SSH Key and 115 Crypto Wallet.",
            examples=["001", "002", "005", "006", "114"],
        ),
        "details": ref("ItemDetails"),
        "overview": ref("ItemOverview"),
    }
    if profile == "full":
        properties.update(
            {
                "trashed": text(
                    "Local trash marker. N = not trashed, D = deleted/trashed."
                ),
                "changerUuid": text("UUID of the last user/device that changed the item."),
                "scope": text("Local visibility scope."),
                "stateRaw": any_value("Raw local integer state value."),
                "validated": any_value("Raw local validation metadata."),
            }
        )
    return obj(
        "One item inside a vault (``vaults[].items[]``).",
        properties,
        required=(
            "uuid",
            "favIndex",
            "createdAt",
            "updatedAt",
            "state",
            "categoryUuid",
            "details",
            "overview",
        ),
        additional=profile in ("importer", "full"),
        comment=(
            "v3 InnerVaultItem field order: uuid, favIndex, createdAt, "
            "updatedAt, state, categoryUuid, details, overview."
        ),
    )


def vault(profile: str) -> dict[str, Any]:
    return obj(
        "One vault inside an account.",
        {
            "attrs": ref("VaultAttrs"),
            "items": array(ref("Item"), "Items in this vault."),
        },
        required=("attrs", "items"),
        additional=profile in ("importer", "full"),
    )


def account(profile: str) -> dict[str, Any]:
    return obj(
        "One account inside the export.",
        {
            "attrs": ref("AccountAttrs"),
            "vaults": array(ref("Vault"), "Vaults in this account."),
        },
        required=("attrs", "vaults"),
        additional=profile in ("importer", "full"),
    )


def definitions(profile: str) -> dict[str, Any]:
    return {
        "ExportAttributes": export_attributes(profile),
        "AccountAttrs": account_attrs(profile),
        "VaultAttrs": vault_attrs(profile),
        "Account": account(profile),
        "Vault": vault(profile),
        "Item": item(profile),
        "ItemDetails": item_details(profile),
        "ItemOverview": item_overview(profile),
        "ItemShortcut": item_shortcut(profile),
        "WatchtowerExclusions": watchtower_exclusions(profile),
        "MigrationDestination": migration_destination(profile),
        "LoginField": login_field(profile),
        "DetailSection": detail_section(profile),
        "DetailSectionField": detail_section_field(profile),
        "SectionFieldValue": section_field_value(profile),
        "InputTraits": input_traits(profile),
        "DocumentAttributes": document_attributes(profile),
        "DetailHtmlForm": html_form(profile),
        "PasswordHistoryEntry": password_history_entry(profile),
        "OverviewUrl": overview_url(profile),
        "Passkey": passkey_value(profile),
        "IconKey": icon_key(profile),
    }


PROFILE_DESCRIPTIONS = {
    "official": (
        "Intersection of the fields the official v3 exporter emits and the "
        "official v3 importer consumes. This is the default round-trip profile: "
        "it deliberately omits passkeys (the exporter path does not emit them) "
        "and local-only metadata such as appIds."
    ),
    "importer": (
        "Every field accepted by the official v3 importer, including the "
        "importer-only passkey field and aliases such as LoginField.type, "
        "DetailHTMLForm.htmlID, OverviewUrl.m, AccountAttrs.fullName and "
        "MigrationDestination.  Objects allow additional properties because "
        "the importer's serde visitors ignore unknown keys.  This schema "
        "describes what the importer can read, not what the official "
        "exporter writes."
    ),
    "exporter": (
        "Fields emitted by the official v3 exporter. In the current matrix this "
        "is the same canonical field set as the official profile: the exporter "
        "does not emit passkeys, and appIds exists only in the local database. "
        "Avatar/icon fields are included when the corresponding files are "
        "present in the ZIP."
    ),
    "full": (
        "All metadata available in the local B5 database, including raw "
        "details/overview objects, trashed/changerUuid/scope/stateRaw/"
        "validated, the complete document encryption metadata, passkeys and "
        "appIds. This is a backup profile and is not guaranteed to import into "
        "the official app."
    ),
}


def build_schema(profile: str) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://onedecrypt.invalid/schema/1pux-{profile}.schema.json",
        "title": f"1PUX v3 export.data ({profile} profile)",
        "description": (
            "JSON Schema for the ``export.data`` entry of a 1PUX ZIP archive. "
            f"{PROFILE_DESCRIPTIONS[profile]} "
            "See docs/schema/README.md for the ZIP layout and the companion "
            "``export.attributes`` schema."
        ),
        "$comment": (
            "Recovered from the shipped 1Password desktop core "
            "(op_import_export::models::translation::onepux::v2/v3). "
            "Primary importer visitors: 0x4740aa0 (ItemDetails), "
            "0x4740d10 (ItemOverview), 0x4740760 (DetailSection), "
            "0x47414a0 (DetailSectionField), 0x4740830 (DocumentAttributes), "
            "0x47412e0 (LoginField), 0x4740370 (OverviewUrl), "
            "0x4740fd0 (SectionFieldValue). Primary exporter path: "
            "0x4c4fb70 (onepux::export closure) and 0x6173620 "
            "(ItemDetails::from). File entries use "
            "``files/<documentId>__<fileName>`` (two underscores); the "
            "format string is at 0x11f79ac, its call site is 0x4c52c4a, and "
            "the importer lookup is 0x4535aae."
        ),
        "type": "object",
        "additionalProperties": profile in ("importer", "full"),
        "required": ["accounts"],
        "properties": {
            "accounts": array(ref("Account"), "Accounts in the export."),
        },
        "$defs": definitions(profile),
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for profile in PROFILES:
        path = OUT_DIR / f"1pux-{profile}.schema.json"
        path.write_text(
            json.dumps(build_schema(profile), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
