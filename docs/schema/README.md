# 1PUX JSON Schemas

These schemas describe the two JSON documents inside a 1PUX ZIP archive:

| File | Schema |
| --- | --- |
| `export.data` | `1pux-official.schema.json`, `1pux-importer.schema.json`, `1pux-exporter.schema.json`, or `1pux-full.schema.json` |
| `export.attributes` | the `ExportAttributes` definition in the same files (`#/$defs/ExportAttributes`) |

The schemas are generated from one declarative model by
`scripts/generate_1pux_schemas.py`, so the four profiles cannot drift apart
silently. They were reconstructed from the shipped 1Password desktop core
(`app.asar.unpacked/index.node`, `op_import_export::models::translation::onepux::v2/v3`),
not from product documentation alone.

## Profiles

| Profile | Purpose | Passkeys | Local-only metadata |
| --- | --- | --- | --- |
| `official` (default) | Fields emitted by the official exporter **and** accepted by the official importer. This is the round-trip profile. | No | No |
| `importer` | Every field the official importer actually consumes, including legacy aliases. | No (accepted but discarded) | Some importer-only legacy fields |
| `exporter` | Fields emitted by the official exporter. | No | No |
| `full` | All metadata in the local B5 database. A backup profile; not guaranteed to import. | Yes | Yes |

In the current reverse-engineering matrix `official` and `exporter` have the
same canonical field set. The names are kept separate because the two code
paths are separate: the exporter never emits passkeys, and the importer
accepts `details.passkey` and the `ItemOverview` `passkey`/`passkeyId` slots
only through `force_none`, which discards their payloads. They are therefore
not part of `importer`; only the raw `full` backup profile keeps them.

`importer` is intentionally a superset of `official`. It includes aliases that
the shipped serde visitors accept but the exporter does not emit, for example:

- `LoginField.type` as an alias for `fieldType`
- `DetailHTMLForm.htmlID` as an alias for `htmlId` (the exporter writes `htmlId`)
- `AccountAttrs.fullName` as an alias for the display name
- `ItemOverview.ainfo`, `URLs`, `MigrationDestination`
- `OverviewUrl.l`, `u`, `m`
- `DocumentAttributes.encryptedSize`, `unencryptedSize`, `integrityHash`, `nonce`, `signingKey`, `encryptionKey`, `uti`

`URLs` is an accepted local/legacy spelling, and local URL entries may use
short `l`/`u`/`m` keys, bare URL strings, or two- or three-element sequences.
The canonical profiles normalize these to the official exporter shape:
lowercase `urls` entries with `label`, `url` and `mode`.  Numeric mode values
are accepted as a local convenience.  When the local `overview.url` is empty,
the first URL entry becomes the primary URL.

`importer` mirrors the binary's mixed unknown-field behavior: the v3
top-level/wrapper structs ignore unknown keys (`additionalProperties: true`),
while the v2 nested structs (`ItemDetails`, `ItemOverview`, `LoginField`,
`DetailSection`, `DetailSectionField`, `DocumentAttributes`,
`DetailHTMLForm`, `AccountAttrs`, `VaultAttrs`, `OverviewUrl`, `InputTraits`,
`MigrationDestination`) call `unknown_field` and therefore reject them
(`additionalProperties: false`). The `official`/`exporter` schemas are strict
throughout.

`full` additionally keeps `trashed`, `changerUuid`, `scope`, `stateRaw`,
`validated`, the raw short-key section representation, the full document
encryption metadata, local passkey metadata and `appIds`.  It is a backup
format, not an import path: the official importer discards passkey payloads.

The `ItemOverview.watchtowerExclusions` field is `null` or an object of
boolean exclusion flags, not a string array. `overview.shortcut` is an
`ItemShortcut` object (`value`, `case_sensitive`), not a bare string.
`VaultAttrs.type` covers the exporter's `P/E/T/U/S/G/M/D` values plus
`Unsupported` in `official`/`exporter`; the importer accepts an arbitrary
string and falls back to `Unsupported`. `Item.state` includes `deleted`
because the serializer and importer both support it; onedecrypt's
`official`/`exporter` extraction policy skips Trash, so its own output
normally contains only `active`/`archived`.

## ZIP layout and file names

A 1PUX archive is a ZIP containing:

```text
export.attributes
export.data
files/
  <documentId>__<fileName>       # Document items and section attachments
  <avatarFileName>               # account/vault avatars, no "__" separator
```

The separator was recovered from the v3 export format string at
`0x4c52c4a`: the template is `{}/{}__{}` with the literal arguments
`"files"`, the document UUID, and the file name. In other words, it is **two**
underscores, not three. The v3 importer builds the same
`files/<documentId>__<fileName>` name before calling `ZipArchive::by_name`
(`0x4534e8b`, `0x4535aae`). The public 1PUX documentation shows a three-
underscore example, but the shipped exporter and importer both use two.

A file reference must have a matching ZIP entry. The importer treats a missing
entry as an import error, so canonical profiles should either include the file
or omit the reference:

- A Document item (`categoryUuid == "006"`) with a missing local blob is
  skipped entirely.
- A section field whose `value.file` cannot be found is dropped.
- Account/vault `avatar` values are cleared unless the avatar blob is actually
  exported, because a non-empty avatar becomes a `files/<name>` lookup.
- Custom `overview.icons` entries are omitted unless the icon blobs are
  exported; `onedecrypt` does not have those blobs in its local cache.

The JSON Schemas cannot validate ZIP entry names or file presence. They
validate only `export.data` / `export.attributes`.

## `export.attributes`

The shipped v3 exporter writes:

```json
{
  "version": 3,
  "description": "1Password Unencrypted Export",
  "timestamp": 1760000000
}
```

The public 1PUX page calls the date field `createdAt`. The desktop exporter
writes `timestamp`, so `official`/`exporter` require `timestamp`. The binary
evidence for the importer accepting `createdAt` is not conclusive, so the
schemas do not declare it as an accepted property.

## Important field notes

### `LoginField.fieldType`

This is a free-form string. Older documentation lists
`T/E/U/N/P/A/TEL`, but the importer does not validate that set, and real vaults
contain values such as `D` and `C`. The schema deliberately does not use an
enum here.

### `SectionFieldValue`

Section field values are an externally tagged enum. A value is a JSON object
with exactly one type key, for example:

```json
{ "concealed": "12345" }
{ "string": "hello" }
{ "file": { "fileName": "a.txt", "documentId": "doc1", "decryptedSize": 10 } }
```

The canonical profiles use the tagged form. The `full` profile preserves the
raw local B5 representation, which can be a scalar or a vendor-specific object.

### `DocumentAttributes`

The canonical exporter/importer shape for a document reference is only:

```json
{
  "fileName": "contract.pdf",
  "documentId": "kzbq4m7xrh2ptnv6ljec3wsdfa",
  "decryptedSize": 4670
}
```

The same object appears in two places:

- `details.documentAttributes` for a Document item
- `details.sections[].fields[].value.file` for an attachment

The importer also accepts legacy encryption metadata (`encryptedSize`,
`integrityHash`, `nonce`, `signingKey`, `encryptionKey`, `uti`); those fields
are documented only in the `importer` and `full` profiles.

### `ItemOverview.appIds`

`appIds` exists in the local B5 overview, but the importer's `ItemOverview`
field visitor does not accept it. It is therefore absent from `official`,
`importer` and `exporter`, and present only in `full`. The same applies to
other local-only keys preserved by `full`.

### Passkeys

The official 1PUX exporter does not emit passkeys. The importer accepts
`details.passkey` and the `ItemOverview` `passkey`/`passkeyId` slots only
through `force_none`: the JSON is consumed and immediately replaced with
`None`, so no credential material reaches the item model. Consequently no
importable profile can transfer a passkey. `official`/`exporter`/`importer`
omit these fields; only the raw `full` backup profile preserves the local
metadata as an opaque JSON value, and importing that profile into the
official app will still not restore the passkey.

### SSH keys

An SSH key is a typed `SectionFieldValue`, not an `ItemDetails` field:
`details.sections[].fields[].value.sshKey`. The value is
`{"privateKey": ..., "metadata": {...}}`; `metadata` is optional, and the
importer derives the public key, fingerprint and key type from `privateKey`
when it is absent. onedecrypt also accepts older local rows that store the
key as a bare string, a single-key `concealed`/`string` wrapper, or under an
`ssh_key`/`private_key` tag, and emits the typed value so the official app
creates an SSH key element instead of a plain text field. For category 114,
a PEM-looking value is recognized even when the local row still calls the
field `string` or `concealed`. A plain string/concealed field is also treated
as an SSH key when its id/title contains `private` and `key`, unless the label
contains a whole-word `passphrase`, `password` or `pin`; a PEM/private-key
value still wins over that label exclusion.

## Validating an export

Install `jsonschema` in an isolated environment and validate `export.data`
extracted from the ZIP:

```bash
uv run --with jsonschema python - <<'PY'
import json, zipfile
from jsonschema import Draft202012Validator

with zipfile.ZipFile("rescue.1pux") as zf:
    data = json.loads(zf.read("export.data"))

schema = json.load(open("docs/schema/1pux-official.schema.json"))
Draft202012Validator(schema).validate(data)
print("export.data matches the official profile")
PY
```

To validate `export.attributes`, use the same file's
`#/$defs/ExportAttributes` schema:

```python
attrs_schema = {"$ref": "#/$defs/ExportAttributes", **schema}
Draft202012Validator(attrs_schema).validate(attributes)
```

## Regenerating the schemas

```bash
uv run python scripts/generate_1pux_schemas.py
```

The generator is the source of truth. Edit the declarative model in
`scripts/generate_1pux_schemas.py`, then regenerate all four files.

## Reverse-engineering references

| Address | Symbol / purpose |
| --- | --- |
| `0x4740aa0` | `v2::ItemDetails` field visitor |
| `0x4740d10` | `v2::ItemOverview` field visitor |
| `0x4740760` | `v2::DetailSection` field visitor |
| `0x47414a0` | `v2::DetailSectionField` field visitor |
| `0x4740830` | `v2::DocumentAttributes` field visitor |
| `0x47412e0` | `v2::LoginField` field visitor |
| `0x4740370` | `v2::OverviewUrl` field visitor |
| `0x4740fd0` | `v2::SectionFieldValue` variant visitor |
| `0x6173620` | `v3::ItemDetails::from` |
| `0x6172b80` | `v3::ItemOverview::from` |
| `0x4c4fb70` | `onepux::export` closure |
| `0x4c52c4a` | `files/{documentId}__{fileName}` format string |
| `0x4534e8b` | v3 importer `files/{}` lookup |
| `0x4535aae` | v3 importer `files/{documentId}__{fileName}` lookup |
| `0x616d610` | `DocumentAttributes::try_into_op_model` |

See `docs/reverse-engineering.md` for the longer narrative and
`docs/schema/1pux-*.schema.json` for the machine-readable definitions.
