"""RSA JWK decoding and RSA-OAEP decryption for 1Password B5 keys."""

from __future__ import annotations

import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .crypto import DecryptionError, b64d


def _int_from_jwk(value: str) -> int:
    return int.from_bytes(b64d(value), "big")


def rsa_private_key_from_jwk(jwk: dict | bytes | str) -> rsa.RSAPrivateKey:
    """Build a ``cryptography`` RSA private key from a 1Password JWK."""
    if isinstance(jwk, (bytes, str)):
        try:
            jwk = json.loads(jwk)
        except json.JSONDecodeError as exc:
            raise DecryptionError(f"invalid RSA JWK: {exc}") from exc
    if not isinstance(jwk, dict):
        raise DecryptionError("invalid RSA JWK: not an object")
    if jwk.get("kty") != "RSA":
        raise DecryptionError(f"expected an RSA JWK, got kty={jwk.get('kty')!r}")
    try:
        n = _int_from_jwk(jwk["n"])
        e = _int_from_jwk(jwk["e"])
        d = _int_from_jwk(jwk["d"])
        p = _int_from_jwk(jwk["p"])
        q = _int_from_jwk(jwk["q"])
    except KeyError as exc:
        raise DecryptionError(f"RSA JWK is missing {exc.args[0]!r}") from exc
    dp = _int_from_jwk(jwk["dp"]) if jwk.get("dp") else d % (p - 1)
    dq = _int_from_jwk(jwk["dq"]) if jwk.get("dq") else d % (q - 1)
    qi = _int_from_jwk(jwk["qi"]) if jwk.get("qi") else pow(q, -1, p)
    try:
        return rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=dp,
            dmq1=dq,
            iqmp=qi,
            public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
        ).private_key()
    except Exception as exc:
        raise DecryptionError(f"invalid RSA private key: {exc}") from exc


def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes, alg: str) -> bytes:
    """RSA-OAEP decrypt using the hash selected by ``rsaHashForAlg``.

    ``RSA-OAEP`` maps to SHA-1 and ``RSA-OAEP-256`` to SHA-256 at 0x700000.
    """
    if alg == "RSA-OAEP-256":
        digest = hashes.SHA256()
    elif alg in ("RSA-OAEP", "", None):
        digest = hashes.SHA1()
    else:
        raise DecryptionError(f"unsupported RSA algorithm {alg!r}")
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=digest), algorithm=digest, label=None),
        )
    except Exception as exc:
        raise DecryptionError("RSA-OAEP decryption failed") from exc


def decrypt_jwe_with_rsa(private_key: rsa.RSAPrivateKey, jwe: dict) -> bytes:
    if not isinstance(jwe, dict):
        raise DecryptionError("expected a JWE object")
    try:
        ciphertext = b64d(jwe["data"])
    except KeyError as exc:
        raise DecryptionError("RSA JWE object is missing data") from exc
    return rsa_oaep_decrypt(private_key, ciphertext, jwe.get("enc"))
