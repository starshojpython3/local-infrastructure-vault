from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken

import config


class CryptoError(Exception):
    pass


class CryptoManager:
    DEFAULT_KDF_NAME = "pbkdf2_sha256"
    DEFAULT_KDF_VERSION = 1

    def __init__(self) -> None:
        self._password_hasher = PasswordHasher(
            time_cost=config.ARGON2_TIME_COST,
            memory_cost=config.ARGON2_MEMORY_COST,
            parallelism=config.ARGON2_PARALLELISM,
            hash_len=config.ARGON2_HASH_LEN,
            salt_len=config.ARGON2_SALT_LEN,
        )

    def hash_master_password(self, master_password: str) -> str:
        return self._password_hasher.hash(master_password)

    def verify_master_password(self, stored_hash: str, master_password: str) -> bool:
        try:
            return self._password_hasher.verify(stored_hash, master_password)
        except Exception:
            return False

    def derive_fernet_key(
        self,
        master_password: str,
        kdf_salt: bytes,
        kdf_name: str | None = None,
        kdf_params: dict[str, Any] | None = None,
    ) -> bytes:
        name = (kdf_name or self.DEFAULT_KDF_NAME).strip().lower()
        if name != self.DEFAULT_KDF_NAME:
            raise CryptoError(f"Unsupported KDF for encryption key: {name}")

        params = kdf_params or {}
        iterations = int(params.get("iterations", config.KDF_ITERATIONS))
        raw = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), kdf_salt, iterations, dklen=32)
        return base64.urlsafe_b64encode(raw)

    @staticmethod
    def default_kdf_params() -> dict[str, Any]:
        return {"iterations": config.KDF_ITERATIONS, "dklen": 32, "hash": "sha256"}

    def generate_kdf_salt(self) -> bytes:
        return os.urandom(config.KDF_SALT_LEN)

    def encrypt_payload(self, key: bytes, payload: dict[str, Any]) -> bytes:
        try:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            return Fernet(key).encrypt(data)
        except Exception as exc:
            raise CryptoError("Failed to encrypt payload") from exc

    def decrypt_payload(self, key: bytes, encrypted_payload: bytes) -> dict[str, Any]:
        try:
            raw = Fernet(key).decrypt(encrypted_payload)
            return json.loads(raw.decode("utf-8"))
        except (InvalidToken, json.JSONDecodeError) as exc:
            raise CryptoError("Failed to decrypt payload") from exc
