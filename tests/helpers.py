from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from onedecrypt.crypto import b64u
from onedecrypt.database import Account, Item, Keyset, Vault


def seal(key: bytes, payload: dict, kid: str) -> dict:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), None)
    return {
        "cty": "b5+jwk+json",
        "kid": kid,
        "enc": "A256GCM",
        "iv": b64u(nonce),
        "data": b64u(ciphertext),
    }


def int_b64(value: int) -> str:
    return b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def rsa_jwk(private_key: rsa.RSAPrivateKey) -> dict:
    numbers = private_key.private_numbers()
    public = numbers.public_numbers
    return {
        "kty": "RSA",
        "kid": "rsa",
        "alg": "RSA-OAEP",
        "n": int_b64(public.n),
        "e": int_b64(public.e),
        "d": int_b64(numbers.d),
        "p": int_b64(numbers.p),
        "q": int_b64(numbers.q),
        "dp": int_b64(numbers.dmp1),
        "dq": int_b64(numbers.dmq1),
        "qi": int_b64(numbers.iqmp),
    }


def sym_jwk(key: bytes, kid: str) -> dict:
    return {"kty": "oct", "kid": kid, "alg": "A256GCM", "k": b64u(key)}


def rsa_seal(public_key: rsa.RSAPublicKey, payload: dict, kid: str) -> dict:
    ciphertext = public_key.encrypt(
        json.dumps(payload).encode(),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
    )
    return {"cty": "b5+jwk+json", "kid": kid, "enc": "RSA-OAEP", "data": b64u(ciphertext)}


def synthetic_account() -> Account:
    from onedecrypt.crypto import b64d

    muk = b64d("6VIFjzKXaHctk44NXr8hOenpgwxWgZebtOlGkPwGK-Y=")
    root_sym = os.urandom(32)
    child_sym = os.urandom(32)
    vault_key = os.urandom(32)
    root_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    child_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root = Keyset(
        uuid="root",
        data={
            "uuid": "root",
            "encryptedBy": "mp",
            "encSymKey": {
                **seal(muk, sym_jwk(root_sym, "root"), "mp"),
                "alg": "PBES2g-HS256",
                "p2c": 100000,
                "p2s": "cA4f6QY7wwUoclj74RMvUg==",
            },
            "encPriKey": seal(root_sym, rsa_jwk(root_rsa), "root"),
        },
    )
    child = Keyset(
        uuid="child",
        data={
            "uuid": "child",
            "encryptedBy": "root",
            "encSymKey": rsa_seal(root_rsa.public_key(), sym_jwk(child_sym, "child"), "root"),
            "encPriKey": seal(child_sym, rsa_jwk(child_rsa), "child"),
        },
    )
    vault = Vault(
        uuid="vault",
        data={
            "vault_type": "P",
            "enc_vault_key": rsa_seal(child_rsa.public_key(), sym_jwk(vault_key, "vaultkey"), "child"),
            "enc_attrs": seal(vault_key, {"name": "Personal", "desc": "", "type": "P"}, "vaultkey"),
        },
    )
    item = Item(
        uuid="item",
        vault_uuid="vault",
        data={
            "category_uuid": "001",
            "state": 0,
            "is_favorite": True,
            "created_at": 1700000000,
            "updated_at": 1700000100,
            "details": seal(
                vault_key,
                {
                    "fields": [
                        {"name": "username", "type": "E", "value": "user@example.com", "designation": "username"},
                        {"name": "password", "type": "P", "value": "secret", "designation": "password"},
                    ],
                    "notesPlain": "note",
                },
                "vaultkey",
            ),
            "overview": seal(
                vault_key,
                {"title": "Example", "url": "https://example.com", "urls": [], "tags": []},
                "vaultkey",
            ),
        },
    )
    vault.items = [item]
    return Account(
        uuid="ACCOUNT",
        data={"user_email": "nobody@example.com", "user_name": "Test", "team_name": "Team"},
        keysets=[root, child],
        vaults=[vault],
    )
