from __future__ import annotations

import json
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from onedecrypt.crypto import (
    DecryptionError,
    b64u,
    jwe_decrypt_json,
    symmetric_key_from_jwk,
)
from onedecrypt.jwk import (
    decrypt_jwe_with_rsa,
    rsa_oaep_decrypt,
    rsa_private_key_from_jwk,
)


def _int_b64(value: int) -> str:
    return b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _jwk(private_key: rsa.RSAPrivateKey, include_crt: bool = True) -> dict:
    numbers = private_key.private_numbers()
    public = numbers.public_numbers
    jwk = {
        "kty": "RSA",
        "n": _int_b64(public.n),
        "e": _int_b64(public.e),
        "d": _int_b64(numbers.d),
        "p": _int_b64(numbers.p),
        "q": _int_b64(numbers.q),
    }
    if include_crt:
        jwk.update(
            {
                "dp": _int_b64(numbers.dmp1),
                "dq": _int_b64(numbers.dmq1),
                "qi": _int_b64(numbers.iqmp),
            }
        )
    return jwk


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_rsa_jwk_round_trip_with_and_without_crt(rsa_key):
    for include_crt in (True, False):
        parsed = rsa_private_key_from_jwk(_jwk(rsa_key, include_crt))
        message = b"vault key"
        ciphertext = parsed.public_key().encrypt(
            message,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
        )
        assert rsa_oaep_decrypt(parsed, ciphertext, "RSA-OAEP") == message


def test_rsa_oaep_sha256_and_jwe_shape(rsa_key):
    message = b"vault key"
    ciphertext = rsa_key.public_key().encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    jwe = {"enc": "RSA-OAEP-256", "data": b64u(ciphertext)}
    assert decrypt_jwe_with_rsa(rsa_key, jwe) == message
    with pytest.raises(DecryptionError):
        rsa_oaep_decrypt(rsa_key, ciphertext, "RSA-OAEP")


def test_symmetric_jwk_and_json_jwe():
    key = os.urandom(32)
    assert symmetric_key_from_jwk({"kty": "oct", "k": b64u(key)}) == key
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, b'{"ok": true}', None)
    assert jwe_decrypt_json(key, {"iv": b64u(nonce), "data": b64u(ciphertext), "enc": "A256GCM"}) == {
        "ok": True
    }
