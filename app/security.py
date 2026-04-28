from __future__ import annotations


import re

SECRET_FIELD_NAMES = {
    "password",
    "ssh_private_key",
    "ssh_passphrase",
    "private_key",
    "passphrase",
    "token",
    "secret",
    "api_key",
}


def normalize_field_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (name or "").strip().lower()).strip("_")


def is_secret_field_name(name: str) -> bool:
    normalized = normalize_field_name(name)
    if not normalized:
        return False
    if normalized in SECRET_FIELD_NAMES:
        return True
    markers = ("password", "passphrase", "private_key", "token", "secret", "api_key")
    return any(marker in normalized for marker in markers)


def mask_secret(value: str) -> str:
    if not value:
        return ""
    return "*" * max(8, min(24, len(value)))
