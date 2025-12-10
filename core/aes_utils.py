# core/aes_utils.py
"""
AES-GCM file encrypt/decrypt utilities.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from argon2 import low_level
from pathlib import Path

MAGIC = b"SAES"
VERSION = 1
KDF_ARGON2 = 1
KDF_PBKDF2 = 2

def derive_key_argon2(password: bytes, salt: bytes, key_len: int = 32) -> bytes:
    return low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        hash_len=key_len,
        type=low_level.Type.ID
    )

def derive_key_pbkdf2(password: bytes, salt: bytes, iterations: int = 200_000, key_len: int = 32) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=iterations)
    return kdf.derive(password)

def encrypt_file(in_path: str, out_path: str, password: str, use_argon2: bool = True):
    password_b = password.encode("utf-8")
    salt = os.urandom(16)
    if use_argon2:
        kdf_id = KDF_ARGON2
        key = derive_key_argon2(password_b, salt)
    else:
        kdf_id = KDF_PBKDF2
        key = derive_key_pbkdf2(password_b, salt)
    with open(in_path, "rb") as f:
        plaintext = f.read()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(bytes([VERSION]))
        f.write(bytes([kdf_id]))
        f.write(bytes([len(salt)]))
        f.write(salt)
        f.write(nonce)
        f.write(ct)

def decrypt_file(in_path: str, out_path: str, password: str):
    with open(in_path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("Invalid encrypted file (magic mismatch).")
        version = f.read(1)[0]
        kdf_id = f.read(1)[0]
        salt_len = f.read(1)[0]
        salt = f.read(salt_len)
        nonce = f.read(12)
        ciphertext = f.read()
    password_b = password.encode("utf-8")
    if kdf_id == KDF_ARGON2:
        key = derive_key_argon2(password_b, salt)
    elif kdf_id == KDF_PBKDF2:
        key = derive_key_pbkdf2(password_b, salt)
    else:
        raise ValueError("Unknown KDF in file.")
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    with open(out_path, "wb") as f:
        f.write(plaintext)
