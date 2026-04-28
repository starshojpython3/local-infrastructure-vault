from __future__ import annotations

from typing import Any

from .models import CredentialView
from .security import is_secret_field_name


class SearchService:
    def __init__(self) -> None:
        self._index: dict[int, str] = {}

    @staticmethod
    def _to_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, dict):
            return " ".join(f"{k}:{SearchService._to_text(v)}" for k, v in value.items())
        if isinstance(value, (list, tuple, set)):
            return " ".join(SearchService._to_text(v) for v in value)
        return str(value)

    def filter_credentials(self, credentials: list[CredentialView], query: str) -> list[CredentialView]:
        self.build_index(credentials)
        q = query.strip().lower()
        if not q:
            return credentials

        out: list[CredentialView] = []
        for cred in credentials:
            indexed_text = self._index.get(cred.id, "")
            if q in indexed_text:
                out.append(cred)
        return out

    def build_index(self, credentials: list[CredentialView], include_secrets: bool = False) -> None:
        self._index = {}
        for cred in credentials:
            p = cred.payload or {}
            non_secret_extra = {}
            extra_payload = p.get("extra")
            if isinstance(extra_payload, dict):
                for key, value in extra_payload.items():
                    if include_secrets or not is_secret_field_name(str(key)):
                        non_secret_extra[key] = value
            bag = [
                cred.organization_name,
                cred.group_name,
                cred.device_name,
                cred.title,
                cred.cred_type,
                cred.environment,
                cred.tags,
                p.get("username"),
                p.get("host"),
                p.get("ip"),
                p.get("port"),
                p.get("url"),
                p.get("ssh_user"),
                p.get("ssh_key_path"),
                p.get("notes"),
                non_secret_extra,
            ]
            if include_secrets:
                bag.extend(
                    [
                        p.get("password"),
                        p.get("ssh_private_key"),
                        p.get("ssh_passphrase"),
                    ]
                )
            self._index[cred.id] = " ".join(self._to_text(x) for x in bag).lower()

    def clear_index(self) -> None:
        self._index.clear()
