from __future__ import annotations

import json

import pytest

from onedecrypt.crypto import (
    DecryptionError,
    MukParams,
    b64d,
    b64u,
    derive_muk,
    hkdf_sha256,
    jwe_decrypt,
    normalize_password,
    parse_secret_key,
)


def test_muk_matches_published_vector():
    params = MukParams(alg="PBES2g-HS256", iterations=100000, salt="cA4f6QY7wwUoclj74RMvUg==")
    muk = derive_muk(
        "A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB",
        "update-clown-squid-bedpost",
        "nobody@example.com",
        params,
    )
    assert b64u(muk) == "6VIFjzKXaHctk44NXr8hOenpgwxWgZebtOlGkPwGK-Y"


def test_hkdf_matches_rfc5869_case_1():
    okm = hkdf_sha256(
        bytes.fromhex("0b" * 22),
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_secret_key_parser_accepts_dashes_lowercase_spaces_and_a2():
    key = parse_secret_key("a3-aswwyb-798jry-ljvd4-23dc2-86tvm-h43eb")
    assert key.format == "A3"
    assert key.account_id == "ASWWYB"
    assert key.key == "798JRYLJVD423DC286TVMH43EB"
    assert parse_secret_key("A3 ASWWYB 798JRYLJVD423DC286TVMH43EB").key == key.key
    a2 = parse_secret_key("A2-ASWWYB-798JRYLJVD423DC286TVMH43E")
    assert a2.format == "A2"
    assert len(a2.key) == 25
    with pytest.raises(ValueError):
        parse_secret_key("A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43E")
    with pytest.raises(ValueError):
        parse_secret_key("A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43E0")


def test_password_normalization_matches_1password():
    assert normalize_password("  ＡＢＣ  ") == "ABC"
    assert normalize_password("\tpassword\n") == "password"
    assert normalize_password("pa ss") == "pa ss"


def test_published_keyset_decrypts():
    muk = b64d("6VIFjzKXaHctk44NXr8hOenpgwxWgZebtOlGkPwGK-Y=")
    iv = b64d("2FF8mtGD55z84h9jMtWAyQ==")
    data = b64d(
        "8OjOA2NqUZZGxXD4r-z4QUfxjvuk23_i0DFAcYxx1r84hmsG1KV1G9iKBZd-kFpfzDgciJD3h8d91OT9D6F8KVqvdmx_q649mWEhiWwVcmRlKRVzgj-eZunS1XHxwHYDhvNvdzKUpNdAp7EKsQCRpiJJ3-eTndQBFMdyeCwkxnqMkuGW326P_mjW5yp_qYpGc4HgpY-_3aEhKimKVGJuxL4I5U5LU2ZFVNNhRIxkjJShtEwtXcTaVwH6"
    )
    plaintext = jwe_decrypt(muk, {"iv": b64u(iv), "data": b64u(data), "enc": "A256GCM"})
    jwk = json.loads(plaintext)
    assert jwk["kid"] == "qn8uimc4l7sofa26yivex24j7q"
    assert b64d(jwk["k"]) == b64d("Sco1rWpdmrLiAeZNtwAlCQsMMqN46AnyGasaMu3EqlQ=")


def test_wrong_gcm_key_fails_closed():
    with pytest.raises(DecryptionError):
        jwe_decrypt(
            b"\x00" * 32,
            {
                "iv": b64u(b"\x00" * 12),
                "data": b64u(b"\x00" * 32),
                "enc": "A256GCM",
            },
        )
