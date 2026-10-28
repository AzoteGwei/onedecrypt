"""Cryptographic primitives used by the 1Password B5 local database.

The constructions here were recovered from ``op`` 2.41.1
(``go.1password.io/core-security/crypto``) and cross-checked against the
published 2SKD test vector from David Schuetz's 1Password research.

References (function addresses in the ``op`` binary):
  * ``crypto.ComputeExistingMUK``           0x6fcd60
  * ``crypto.computePBES2gHS256MUK``        0x6fd5a0
  * ``crypto.(*SecretKey).HKDF``            0x700e60
  * ``crypto.(*MUKParams).SaltBytes``       0x6fd320
  * ``crypto.normalizePassword``            0x6fda80
  * ``crypto.decryptContent``               0x7006c0
  * ``crypto.(*SymmetricKey).DecryptV1``    0x703420
  * ``crypto.(*RSAPrivateKey).DecryptV1``   0x6fe660
  * ``crypto.rsaHashForAlg``                0x700000
"""

from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# The 1Password secret-key alphabet.  Characters 0, 1, O and I are excluded
# to avoid transcription mistakes.  See crypto.NewSecretKey (0x701120).
SECRET_KEY_ALPHABET = set("23456789ABCDEFGHJKLMNPQRSTVWXYZ")


class DecryptionError(Exception):
    """Raised when a ciphertext cannot be authenticated or parsed."""


def b64d(value: str | bytes) -> bytes:
    """Decode standard or URL-safe base64, with or without padding.

    1Password mixes both alphabets across the database, the API and its
    exports.  The Go helper is ``RelaxedBase64URLDecodeString``.
    """
    if isinstance(value, bytes):
        value = value.decode("ascii")
    value = "".join(value.split())
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, validate=False)
    except Exception as exc:  # pragma: no cover - input dependent
        raise DecryptionError(f"invalid base64 value: {exc}") from exc


def b64u(data: bytes) -> str:
    """Encode URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF with SHA-256.

    Go's ``golang.org/x/crypto/hkdf.New`` is used with an explicit salt in
    every call site relevant to the MUK.  The one-shot ``cryptography``
    implementation matches it byte-for-byte.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor operands must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


@dataclass(frozen=True)
class SecretKey:
    """A parsed 1Password Secret Key (``A3-XXXXXX-...``)."""

    format: str
    account_id: str
    key: str

    def hkdf(self) -> bytes:
        """Return the 32-byte Secret Key contribution to the MUK.

        This mirrors ``(*SecretKey).HKDF`` at 0x700e60:
        HKDF-SHA256(ikm=key, salt=account_id, info=version), 32 bytes.
        The values are the literal ASCII characters displayed to the user,
        not the base32-decoded bits.
        """
        return hkdf_sha256(
            self.key.encode("ascii"),
            self.account_id.encode("ascii"),
            self.format.encode("ascii"),
            32,
        )


def parse_secret_key(value: str) -> SecretKey:
    """Parse the user-supplied Secret Key.

    Accepts the canonical hyphenated form, a form with spaces, or the raw
    concatenated form.  Matching is case-insensitive; ``NewSecretKey``
    upper-cases the input before validating it.
    """
    cleaned = value.strip().upper()
    cleaned = "".join(ch for ch in cleaned if not ch.isspace() and ch != "-")
    if not cleaned:
        raise ValueError("secret key is empty")
    invalid = sorted({ch for ch in cleaned if ch not in SECRET_KEY_ALPHABET})
    if invalid:
        raise ValueError(
            "secret key contains characters outside the 1Password alphabet: "
            + " ".join(invalid)
        )
    if len(cleaned) < 8:
        raise ValueError("secret key is too short")
    version = cleaned[:2]
    if version not in ("A2", "A3"):
        raise ValueError(f"unsupported secret key version {version!r} (expected A2 or A3)")
    account_id = cleaned[2:8]
    key = cleaned[8:]
    expected = 26 if version == "A3" else 25
    if len(key) != expected:
        raise ValueError(
            f"secret key version {version} expects {expected} key characters, "
            f"got {len(key)}"
        )
    return SecretKey(format=version, account_id=account_id, key=key)


def normalize_password(password: str) -> str:
    """Normalize a master password the same way 1Password does.

    ``crypto.normalizePassword`` at 0x6fda80 applies Unicode NFKD and trims
    leading/trailing whitespace.  It does not lower-case the password.
    """
    return unicodedata.normalize("NFKD", password).strip()


@dataclass(frozen=True)
class MukParams:
    alg: str
    iterations: int
    salt: str

    @classmethod
    def from_jwe(cls, jwe: dict) -> "MukParams":
        alg = jwe.get("alg")
        iterations = jwe.get("p2c")
        salt = jwe.get("p2s")
        if not alg or not isinstance(iterations, int) or iterations <= 0 or not salt:
            raise DecryptionError("encrypted key is missing valid MUK parameters")
        return cls(alg=alg, iterations=iterations, salt=salt)

    def salt_bytes(self) -> bytes:
        return b64d(self.salt)


def derive_muk(
    secret_key: str | SecretKey,
    password: str,
    email: str,
    params: MukParams,
) -> bytes:
    """Derive the Master Unlock Key (2SKD).

    Recovered from ``crypto.ComputeExistingMUK`` (0x6fcd60) and
    ``crypto.computePBES2gHS256MUK`` (0x6fd5a0):

        secret     = HKDF-SHA256(secret_key.key, account_id, version)
        email      = strings.ToLower(email)
        salt       = HKDF-SHA256(p2s, email, alg)
        derived    = PBKDF2-HMAC-SHA256(normalize(password), salt, p2c, 32)
        MUK        = derived XOR secret

    The derivation in the binary uses the literal ASCII Secret Key parts.
    """
    sk = parse_secret_key(secret_key) if isinstance(secret_key, str) else secret_key
    if params.alg != "PBES2g-HS256":
        raise DecryptionError(
            f"unsupported MUK algorithm {params.alg!r}; this build only implements "
            "PBES2g-HS256 (the algorithm used by 1Password 8 accounts)"
        )

    secret_part = sk.hkdf()
    password_salt = hkdf_sha256(
        params.salt_bytes(),
        email.lower().encode("utf-8"),
        params.alg.encode("ascii"),
        32,
    )
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        normalize_password(password).encode("utf-8"),
        password_salt,
        params.iterations,
        32,
    )
    return xor_bytes(derived, secret_part)


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """AES-256-GCM with no additional authenticated data.

    1Password's JWE-B ``data`` field is ciphertext||tag; ``iv`` is the nonce.
    Go's GCM accepts non-12-byte nonces (the older 16-byte IVs are present in
    exported data), and Python's ``cryptography`` does the same GHASH-based
    derivation.
    """
    if len(key) != 32:
        raise DecryptionError(f"A256GCM key must be 32 bytes, got {len(key)}")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise DecryptionError("AES-GCM authentication failed") from exc


def jwe_decrypt(key: bytes, jwe: dict) -> bytes:
    """Decrypt a B5 JWE-B object with a raw 32-byte symmetric key."""
    if not isinstance(jwe, dict):
        raise DecryptionError("expected a JWE object")
    if jwe.get("enc") not in (None, "A256GCM"):
        raise DecryptionError(f"unsupported content encryption {jwe.get('enc')!r}")
    try:
        nonce = b64d(jwe["iv"])
        ciphertext = b64d(jwe["data"])
    except KeyError as exc:
        raise DecryptionError("JWE object is missing iv/data") from exc
    return aes_gcm_decrypt(key, nonce, ciphertext)


def jwe_decrypt_json(key: bytes, jwe: dict) -> dict:
    try:
        return json.loads(jwe_decrypt(key, jwe))
    except json.JSONDecodeError as exc:
        raise DecryptionError(f"decrypted payload is not JSON: {exc}") from exc


def symmetric_key_from_jwk(jwk: dict | bytes | str) -> bytes:
    """Extract the raw key from an ``oct`` JWK."""
    if isinstance(jwk, (bytes, str)):
        try:
            jwk = json.loads(jwk)
        except json.JSONDecodeError as exc:
            raise DecryptionError(f"invalid symmetric JWK: {exc}") from exc
    if not isinstance(jwk, dict):
        raise DecryptionError("invalid symmetric JWK: not an object")
    if jwk.get("kty") not in (None, "oct"):
        raise DecryptionError(f"expected an oct JWK, got kty={jwk.get('kty')!r}")
    try:
        key = b64d(jwk["k"])
    except KeyError as exc:
        raise DecryptionError("symmetric JWK is missing 'k'") from exc
    if len(key) != 32:
        raise DecryptionError(f"expected a 256-bit symmetric key, got {len(key) * 8} bits")
    return key
