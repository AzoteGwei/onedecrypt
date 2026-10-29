# Reverse-engineering notes

This document records how the decryptor was derived and which evidence backs
each step.  It is intentionally separate from the user-facing README because
it contains addresses and internal identifiers that only matter when the
implementation is audited or updated.

## Targets

| Artifact | Identity | Role |
| --- | --- | --- |
| `op.zip` → `op` | 1Password CLI 2.41.1, Go 1.26.10, ELF x86-64, stripped | Primary target for the cryptographic logic |
| `~/.config/1Password/1password.sqlite` | 1Password 8.11/8.12 desktop database, schema version 61 | Data source: accounts, keysets, vaults, items |
| `/opt/1Password/resources/app.asar.unpacked/index.node` | 1Password 8.12.32 desktop core (Rust, not stripped) | Confirmation of the 1PUX v3 schema and DB item-state semantics |

The database is written by the **desktop app**, not by the CLI.  The CLI does
not create `1password.sqlite`.  However, the CLI's Go module
`go.1password.io/core-security` contains the same B5 key hierarchy and JWE
constructions, which is why the Go binary is the right place to recover the
format.  The desktop core was used only to confirm the export wrapper and the
meaning of the integer `state` column.

## Symbol recovery

`op` has no ELF symbol table, but it is a Go binary and still contains
`.gopclntab`.  GoReSym recovered 34,145 functions and the Go type graph;
Binary Ninja was used to decompile the relevant functions and to inspect the
desktop core.  The helper script `tools/gopcln.py` parses the Go 1.26 pclntab
directly (the `textStart` field was removed in Go 1.26; the text base comes
from the ELF `.text` section).

## 2SKD: Secret Key + Master Password → MUK

Relevant functions in `op`:

| Address | Symbol | Finding |
| --- | --- | --- |
| `0x6fcd60` | `crypto.ComputeExistingMUK` | Dispatches on the MUK algorithm string: `PBES2g-HS256` (11 chars) and `PBES2-HS256` (12 chars) |
| `0x6fd5a0` | `crypto.computePBES2gHS256MUK` | Current 1Password 8 derivation |
| `0x6fd360` | `crypto.computePBES2HS256MUK` | Older derivation; uses `prehashPassword` |
| `0x6fd320` | `crypto.(*MUKParams).SaltBytes` | `p2s` is base64-decoded with `RelaxedBase64URLDecodeString` |
| `0x700e60` | `crypto.(*SecretKey).HKDF` | `HKDF-SHA256(ikm=secret, salt=account_id, info=version)` → 32 bytes |
| `0x6fda80` | `crypto.normalizePassword` | Unicode NFKD (`norm.Form(3)`) then leading/trailing whitespace removal |
| `0x6fd080` | `crypto.GenerateNewMUK` | Confirms `p2s` is 16 random bytes and the default iteration count is 100,000 for newly created MUKs |
| `0x6fd880` | `crypto.prehashPassword` | Older `PBES2-HS256`: NFKD/trim, SHA-256, base64, strip `=`.  Not implemented by this tool because the current accounts use `PBES2g-HS256`. |

Decompiled logic for `PBES2g-HS256`:

```text
secret       = HKDF-SHA256(ikm = SecretKey.key,
                           salt = SecretKey.account_id,
                           info = SecretKey.version, len = 32)
email_lower  = strings.ToLower(account.email)
password_salt= HKDF-SHA256(ikm = base64url_decode(p2s),
                           salt = email_lower,
                           info = "PBES2g-HS256", len = 32)
derived      = PBKDF2-HMAC-SHA256(password = normalizePassword(password),
                                  salt = password_salt,
                                  iterations = p2c, dkLen = 32)
MUK          = derived XOR secret
```

The Secret Key is split exactly as displayed:

```text
A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB
^^ ^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^
|  |      secret (26 chars for A3, 25 for A2)
|  account ID (6 chars)
version ("A3" / "A2")
```

The ASCII characters are used directly by HKDF; they are not base32-decoded.
This was confirmed with the published 2SKD vector:

```text
Secret Key  A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB
Password    update-clown-squid-bedpost
Email       nobody@example.com
p2s         cA4f6QY7wwUoclj74RMvUg==
p2c         100000
MUK         6VIFjzKXaHctk44NXr8hOenpgwxWgZebtOlGkPwGK-Y=
```

`src/onedecrypt/cli.py self-test` checks both this MUK vector and the
associated AES-GCM keyset ciphertext.

## Keyset graph

`EncryptedKeysetV1.DecryptV1` at `0x6f9be0` shows the order:

1. Read the MUK parameters from `encSymKey` (`alg`, `p2c`, `p2s`).
2. Derive the MUK (above).
3. AES-256-GCM decrypt `encSymKey` with the MUK.  The plaintext is an `oct`
   JWK.
4. AES-256-GCM decrypt `encPriKey` with that symmetric key.  The plaintext is
   an RSA private JWK.
5. If `encSignKey` exists, decrypt it with the same symmetric key and parse an
   ECDSA private JWK.

Root keysets have `encryptedBy: "mp"`.  Child keysets have
`encryptedBy: <parent keyset UUID>` and their `encSymKey` is RSA-OAEP
encrypted with the parent's public key.  The implementation resolves this
graph iteratively (`resolve_keysets` in `src/onedecrypt/decrypt.py`).

## Vault and item decryption

| Address | Symbol | Finding |
| --- | --- | --- |
| `0xb59e60` | `local.decryptedKeyForVault` | Looks up the keyset named by `enc_vault_key.kid`, decrypts the vault key, parses a symmetric JWK |
| `0xb5a280` | `local.decryptedAttrsForVault` | AES-GCM decrypts `enc_attrs`, then JSON |
| `0xb596a0` | `local.(*DecryptedVault).DecryptVaultItem` | AES-GCM decrypts `details` and `overview` with the vault key |
| `0x703420` | `crypto.(*SymmetricKey).DecryptV1` | Base64url-decodes `iv`/`data`, checks `kid`, calls `DecryptRaw` |
| `0x703760` | `crypto.(*SymmetricKey).DecryptRaw` | AES-256-GCM; `iv` must be 12 bytes in the current path; data is ciphertext‖tag; no AAD |
| `0x7006c0` | `crypto.decryptContent` | Same GCM construction, used by the content layer |
| `0x6fe660` | `crypto.(*RSAPrivateKey).DecryptV1` | RSA-OAEP decrypt of `enc_vault_key`; `kid` must match |
| `0x700000` | `crypto.rsaHashForAlg` | `RSA-OAEP` → SHA-1, `RSA-OAEP-256` → SHA-256 |

The older 16-byte IVs seen in exported test data also decrypt correctly: Go's
GCM accepts arbitrary nonce lengths and Python `cryptography` uses the same
GHASH-based J0 derivation.

## Database schema and B5 payloads

The outer database rows are JSON with snake_case keys:

```text
accounts.data : account metadata (email, names, sign-in URL, keysets)
vaults.data   : vault_type, enc_vault_key, enc_attrs, ...
items.data    : category_uuid, changer_uuid, created_at, updated_at,
                is_favorite, state, details, overview
```

`details` and `overview` are JWE-B objects:

```json
{"cty":"b5+jwk+json","kid":"<vault-key-id>","enc":"A256GCM",
 "iv":"<base64url nonce>","data":"<base64url ciphertext||tag>"}
```

The decrypted item bodies use the B5/`op_model_item` JSON schema:

- Login details: `fields` (username/password/designation), `notesPlain`,
  `sections`, `passwordHistory`.
- Password details: `password`, `notesPlain`, `sections`.
- Document details: `documentAttributes` with `fileName`, `documentId`,
  `nonce`, `integrityHash`, `encryptionKey` (a symmetric JWK), and sizes.
- Overview: `title`, `url`, `urls`, `tags`, `ps`, `pbe`, `pgrng`, `ainfo`,
  `icons`, `scope`, `b5UserUUID`.

The strict 1PUX v3 exporter converts the login `fields` array to
`loginFields`, maps short section fields (`t/n/k/v/a`) to the official
`title/id/value/...` form, maps `ainfo` to `subtitle`, and emits only the
fields present in the selected schema profile.  SSH keys are a
`SectionFieldValue` variant, not an `ItemDetails` field; older local rows may
store the key as bare text, a single-key `concealed`/`string` wrapper, or a
`ssh_key`/`private_key` tag, so the exporter normalizes all of those to
`{"sshKey": {"privateKey": ...}}`.  The importer derives the missing public
key/fingerprint/key type from the private key.  For category 114, a
PEM/private-key value is recognized even when the row still calls the field
`string` or `concealed`; a plain field whose id/title mentions a private key
is also converted, except for whole-word passphrase/password/pin labels, and
key-looking values take precedence over that exclusion.

Passkeys are local-only.  The official exporter drops the local
`Option<Passkey>` when it builds `ItemDetails`, and the importer accepts the
`passkey`/`passkeyId` JSON keys only through `force_none`, which discards
their payloads.  A 1PUX file therefore cannot transfer a usable passkey; only
the `full` backup profile keeps the local metadata.

The integer `state` field is interpreted using the desktop SQL found in
`index.node`:

```sql
SELECT count(*) FROM items WHERE data ->> '$.state' = 0
-- active items
SELECT count(*) FROM items WHERE data ->> '$.state' != 0
-- inactive items
```

The exporter maps `0 → active`, `1 → archived`, `2 → deleted`.  The official
v3 `InnerVaultItem` has no `trashed` field, so it is not emitted.

## Document files

`local.DecryptFile` at `0xb577a0`:

1. Read the file blob (normally
   `~/.config/1Password/files/<account_uuid>/<documentId>`).
2. Check `integrityHash` (SHA-256, base64url of the digest).
3. Decode `nonce` and the per-file `encryptionKey` JWK from
   `documentAttributes`.
4. AES-256-GCM decrypt the file bytes with that key and nonce.

The exporter writes the plaintext as `files/<documentId>__<fileName>` and
reduces `documentAttributes` to the `fileName`, `documentId`, and
`decryptedSize` fields expected by 1PUX.

## 1PUX schema confirmation

The desktop core contains the Rust crate
`op_import_export::models::translation::onepux::v3`.  Relevant symbols and
strings:

- `LocalVaultExporter::convert` at `0x3c26e00`.
- `InnerVaultItem as From<op_model_item::Item>` at `0x616da10` (BN view
  address; the file vaddr is `0x5d6da10`).
- `ItemDetails as From<op_model_item::ItemDetails>` at `0x6173620`.
- `ItemOverview as From<op_model_item::ItemOverview>` at `0x6172b80`.
- `DataModel as From<ExportInfo>` at `0x616e320`.
- `Attributes::default` at `0x6161b10` (description + timestamp + version).
- The writer strings `export.attributes` / `export.data` / `files` at file
  offset `0xf35cb8`.
- `ItemState` deserializer at `0x4530ba0` compares the strings `active`,
  `archived`, and `deleted`.
- The item field dispatcher contains `uuid`, `favIndex`, `categoryUuid`,
  `state`, `overview`, `details`, `createdAt`, `updatedAt`.  `InnerVaultItem`
  has exactly eight fields.
- The v2 `ItemDetails` field dispatcher (reused by v3) has `htmlForm`,
  `loginFields`, `notesPlain`, `sections`, `passwordHistory`, `password`,
  `passkey` (force_none), and `documentAttributes`. It has no `sshKey`
  field: SSH keys live in `SectionFieldValue`.
- The v3 `ItemOverview` importer dispatcher has 20 accepted strings,
  including `subtitle`/`ainfo`, `icons`, `shortcut`, `locations`,
  `b5UserUUID`/`b5UserUuid`, `watchtowerExclusions`,
  `MigrationDestination`/`migrationDestination`, `passkey`/`passkeyId`.
  `appIds` is **not** among them.
- `DetailSection` has `title`, `name`, `fields`, `hideAddAnotherField`.
- `DetailSectionField` has `title`, `id`, `value`, `guarded`, `multiline`,
  `dontGenerate`, `indexAtSource`, `placeholder`, `inputTraits`,
  `clipboardFilter`; input traits are `keyboard`, `correction`,
  `capitalization`.
- `DocumentAttributes` has ten importer fields; the plaintext 1PUX export
  uses `fileName`, `documentId`, and `decryptedSize`.

The exporter therefore writes:

```text
export.attributes = {version: 3, description: "1Password Unencrypted Export", timestamp}
export.data       = {accounts: [{attrs, vaults: [{attrs, items: [...]}]}]}
files/            = optional decrypted documents
```

## Schema profiles

The exporter exposes four profiles derived from the reverse-engineered
capability sets:

| Profile | Selection rule |
| --- | --- |
| `official` | fields emitted by the official exporter **and** consumed by the official importer |
| `importer` | fields consumed by the official importer |
| `exporter` | fields emitted by the official exporter |
| `full` | all locally available metadata, including fields only present in the local database |

The current matrix has the same field sets for `official` and `exporter`.
`importer` adds legacy aliases accepted by the serde visitors, but not the
`passkey`/`passkeyId` slots: those are consumed by `force_none` and discarded,
so they have no import effect.  The names remain separate so a future
correction to either code path cannot silently change the meaning of a
profile.  `full` additionally keeps `trashed`, `changerUuid`, `scope`,
`stateRaw`, `validated`, raw short-key section fields, local passkey
metadata, `appIds`, and the full document encryption metadata.

Two field-set corrections from the importer analysis:

- `appIds` exists in the local B5 overview but is **not** in the importer's
  `ItemOverview` visitor.  It is therefore local-only (`full`) and absent from
  `official`/`importer`/`exporter`.
- The official exporter omits Trash.  `official`/`exporter` therefore export
  only `active`/`archived` items; `importer` also emits `deleted` because the
  importer's `ItemState` visitor accepts it, and `full` keeps everything.

The machine-readable versions of these profiles, with per-field comments and
the exact ZIP file naming rules, are in `docs/schema/`.

## 1PUX import path

The official importer is the reverse direction of the same v3 models.  The
relevant BN symbols are:

| BN address | Symbol | Role |
| --- | --- | --- |
| `0x616c270` | `InnerVaultItem as IntoOpModel<op_model_item::Item>::into_op_model` | v3 item -> internal item |
| `0x616c610` | `v2::ItemDetails as IntoOpModel<op_model_item::ItemDetails>` | details -> internal details |
| `0x6168eb0` | `v2::ItemOverview as IntoOpModel<op_model_item::ItemOverview>` | overview -> internal overview |
| `0x616e070` | `v2::DetailSectionField as IntoOpModel<op_model_item::SectionField>` | section field + typed value |
| `0x616d610` | `v2::DocumentAttributes as TryIntoOpModel<op_model_item::DocumentAttributes>` | plaintext or encrypted file reference |
| `0x4533ec0` | `v3::import` tokio task | ZIP/JSON parsing and import driver |
| `0x4c84fa0` | `v3::import_files` | associate `files/` entries with items |

Import flow:

1. Read `export.attributes` (`version`, `description`, `timestamp`), then
   `export.data` (`accounts -> vaults -> items`).
2. Deserialize each `InnerVaultItem` into an internal `op_model_item::Item`.
   The category string is parsed as a `Category`; `state` is
   `active`/`archived`/`deleted`; `uuid`, `favIndex`, timestamps, `details`,
   and `overview` are copied.
3. Deserialize `ItemDetails` into the internal details model.  The canonical
   fields are `htmlForm`, `loginFields`, `notesPlain`, `sections`,
   `passwordHistory`, `password`, `passkey` (force_none), and
   `documentAttributes`.
4. Deserialize `ItemOverview` into the internal overview model.  The visitor
   accepts `ainfo`, `subtitle`, `b5UserUUID`/`b5UserUuid`, `icons`,
   `URLs`/`urls`, `tags`, `title`, `url`, `ps`, `pbe`, `pgrng`,
   `passkeyId`/`passkey`, `MigrationDestination`/`migrationDestination`,
   `watchtowerExclusions`, `shortcut`, and `locations`.  `appIds` is **not**
   accepted; it exists only in the local B5 overview.  The
   `passkey`/`passkeyId` values are force-none and do not reach the model.
5. `DocumentAttributes` has two paths:
   - Plaintext 1PUX: `fileName`, `documentId`, `decryptedSize`; the file body
     is read from `files/<documentId>__<fileName>`.
   - Encrypted/import-file path: `encryptionKey`, `nonce`, `integrityHash`,
     `encryptedSize`, `signingKey`, etc.; this is used by other importers, not
     by a plaintext 1PUX export.
6. `import_files` matches file entries to `documentAttributes` and section
   file fields.  Missing files are an import error; the app layer then writes
   the resulting items into the target vault.
7. The v3 parser does **not** create accounts or vaults.  Account/vault
   creation, keyset encryption, and sync are handled by the surrounding app
   layer, not by the 1PUX translation code.

The schema-level importer accepts `details.passkey` and the
`ItemOverview` `passkey`/`passkeyId` slots, but every one of those values is
deserialized with `force_none` and replaced by `None`.  There is therefore no
1PUX import path for passkeys: the payload never reaches the internal
`op_model_item` structures.  The official exporter also drops the local
`Option<Passkey>` when serializing `ItemDetails`.  `official`, `exporter` and
`importer` omit passkeys; only the raw `full` backup profile preserves the
local metadata, and importing it still does not restore the passkey.

## Verification

```bash
uv run pytest
uv run onedecrypt self-test
uv run onedecrypt list-accounts
```

An end-to-end check requires the account's real Secret Key and Master
Password.  The tool deliberately does not attempt to recover or bypass them.
If the MUK is wrong, the root keyset's AES-GCM tag fails and the tool exits
with status 3 without writing an export.
