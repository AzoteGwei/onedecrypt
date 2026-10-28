"""Schema model primitives for the 1PUX JSON Schema generator.

The shared shapes for accounts, vaults, login fields, documents and section
values live here.  The item/section object model and the generator entry
point are added in the next CL.
"""

from __future__ import annotations

from typing import Any

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
            "Postal address value. The concrete object is an op-model Address.",
            any_value("Address object."),
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
            "Date value. The official model stores an epoch timestamp; older "
            "exports may use a string.",
            {"type": ["integer", "string"], "description": "Date value."},
        ),
        variant("email", "Email address.", text("Email address.", format="email")),
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
            "Month/year value. The official model stores YYYYMM as an integer; "
            "older exports may use a string.",
            {"type": ["integer", "string"], "description": "Month/year value."},
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
            any_value("SSH key object or string."),
        ),
        variant(
            "ssoLogin",
            "SSO login value.",
            any_value("SSO login object or string."),
        ),
        variant("string", "Plain string value.", text("String value.")),
        variant("totp", "One-time-password secret/URI.", text("TOTP value.")),
        variant(
            "unsupported",
            "A value the importer could not classify. Preserved so no data is lost.",
            any_value("Unsupported value."),
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

