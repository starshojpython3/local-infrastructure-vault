from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class VaultMeta:
    is_initialized: bool
    password_hash: str | None = None
    kdf_salt: bytes | None = None
    kdf_name: str | None = None
    kdf_version: int | None = None
    kdf_params: dict[str, Any] | None = None


@dataclass
class CredentialView:
    id: int
    organization_id: int
    organization_name: str
    group_id: int | None
    group_name: str | None
    device_id: int | None
    device_name: str | None
    title: str
    cred_type: str
    environment: str
    tags: str
    payload: dict[str, Any]
    created_at: str
    updated_at: str
