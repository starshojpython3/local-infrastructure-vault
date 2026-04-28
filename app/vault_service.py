from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from .crypto import CryptoManager
from .database import Database
from .models import CredentialView, VaultMeta


DEFAULT_SECRET_FIELDS = {
    "username": "",
    "password": "",
    "host": "",
    "ip": "",
    "port": "",
    "url": "",
    "ssh_user": "",
    "ssh_key_path": "",
    "ssh_private_key": "",
    "ssh_passphrase": "",
    "notes": "",
    "extra": {},
}


METADATA_ENCRYPTED_VERSION = 2
OPAQUE_METADATA_PLACEHOLDER = "__encrypted__"


class VaultService:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.crypto = CryptoManager()
        self._session_key: bytes | None = None

    def get_vault_meta(self) -> VaultMeta:
        row = self.db.fetchone("SELECT password_hash, kdf_salt, kdf_name, kdf_version, kdf_params FROM vault_meta WHERE id=1")
        if not row:
            return VaultMeta(is_initialized=False)
        kdf_params = None
        if row["kdf_params"]:
            try:
                kdf_params = json.loads(row["kdf_params"])
            except json.JSONDecodeError:
                kdf_params = None
        return VaultMeta(
            is_initialized=True,
            password_hash=row["password_hash"],
            kdf_salt=base64.b64decode(row["kdf_salt"]),
            kdf_name=row["kdf_name"] or self.crypto.DEFAULT_KDF_NAME,
            kdf_version=row["kdf_version"] or self.crypto.DEFAULT_KDF_VERSION,
            kdf_params=kdf_params,
        )

    def initialize_vault(self, master_password: str) -> None:
        hashed = self.crypto.hash_master_password(master_password)
        kdf_salt = self.crypto.generate_kdf_salt()
        kdf_name = self.crypto.DEFAULT_KDF_NAME
        kdf_version = self.crypto.DEFAULT_KDF_VERSION
        kdf_params = self.crypto.default_kdf_params()
        self.db.execute(
            "INSERT INTO vault_meta(id, password_hash, kdf_salt, kdf_name, kdf_version, kdf_params) VALUES(1, ?, ?, ?, ?, ?)",
            (hashed, base64.b64encode(kdf_salt), kdf_name, kdf_version, json.dumps(kdf_params)),
        )

    def set_session_key(self, key: bytes) -> None:
        self._session_key = key

    def clear_session(self) -> None:
        self._session_key = None

    def unlock(self, master_password: str) -> bytes | None:
        meta = self.get_vault_meta()
        if not meta.is_initialized or not meta.password_hash or not meta.kdf_salt:
            return None
        if not self.crypto.verify_master_password(meta.password_hash, master_password):
            return None
        key = self.crypto.derive_fernet_key(
            master_password,
            meta.kdf_salt,
            kdf_name=meta.kdf_name,
            kdf_params=meta.kdf_params,
        )
        self._session_key = key
        self._migrate_sensitive_metadata(key)
        return key

    def _encrypt_entity_name(self, key: bytes, name: str) -> bytes:
        return self.crypto.encrypt_payload(key, {"name": name.strip()})

    def _decrypt_entity_name(self, key: bytes, encrypted_data: bytes | None, fallback: str | None) -> str:
        if encrypted_data:
            payload = self.crypto.decrypt_payload(key, encrypted_data)
            return str(payload.get("name", "")).strip()
        return (fallback or "").strip()

    @staticmethod
    def _opaque_name_token() -> str:
        return f"enc_{secrets.token_hex(8)}"

    @staticmethod
    def _is_opaque_value(value: Any) -> bool:
        text = str(value or "").strip()
        return text == "" or text == OPAQUE_METADATA_PLACEHOLDER or text.startswith("enc_")

    @staticmethod
    def _opaque_metadata_placeholder() -> str:
        return OPAQUE_METADATA_PLACEHOLDER

    def _encrypt_credential_record(
        self,
        key: bytes,
        title: str,
        cred_type: str,
        environment: str,
        tags: str,
        payload: dict[str, Any],
    ) -> bytes:
        merged = {
            "schema_version": 2,
            "metadata_encrypted_version": METADATA_ENCRYPTED_VERSION,
            "title": title.strip(),
            "type": cred_type,
            "environment": environment,
            "tags": tags.strip(),
        }
        merged.update(DEFAULT_SECRET_FIELDS)
        merged.update(payload)
        return self.crypto.encrypt_payload(key, merged)

    def _decrypt_credential_record(self, key: bytes, row: Any) -> tuple[str, str, str, str, dict[str, Any]]:
        decrypted = self.crypto.decrypt_payload(key, row["encrypted_payload"])
        payload: dict[str, Any] = dict(DEFAULT_SECRET_FIELDS)
        for field in DEFAULT_SECRET_FIELDS:
            if field in decrypted:
                payload[field] = decrypted[field]

        title = str(decrypted.get("title") or row["title"] or "")
        cred_type = str(decrypted.get("type") or row["type"] or "other")
        environment = str(decrypted.get("environment") or row["environment"] or "other")
        tags = str(decrypted.get("tags") or row["tags"] or "")
        return title, cred_type, environment, tags, payload

    def _needs_entity_metadata_migration(self, row: Any) -> bool:
        if (
            row["encrypted"]
            and row["encrypted_data"]
            and int(row["metadata_encrypted_version"] or 0) >= METADATA_ENCRYPTED_VERSION
            and self._is_opaque_value(row["name"])
        ):
            return False
        return True

    def _needs_credential_metadata_migration(self, key: bytes, row: Any) -> bool:
        if row["encrypted_payload"]:
            try:
                payload = self.crypto.decrypt_payload(key, row["encrypted_payload"])
                if (
                    int(payload.get("metadata_encrypted_version", 0)) >= METADATA_ENCRYPTED_VERSION
                    and int(row["metadata_encrypted_version"] or 0) >= METADATA_ENCRYPTED_VERSION
                    and row["encrypted"]
                    and self._is_opaque_value(row["title"])
                    and self._is_opaque_value(row["type"])
                    and self._is_opaque_value(row["environment"])
                    and self._is_opaque_value(row["tags"])
                ):
                    return False
            except Exception:
                return True
        return True

    def _cleanup_sqlite_after_migration(self, conn: Any) -> None:
        try:
            conn.execute("PRAGMA secure_delete = ON;")
        except Exception:
            pass
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except Exception:
            pass
        try:
            conn.execute("PRAGMA journal_mode=DELETE;")
        except Exception:
            pass
        try:
            conn.execute("VACUUM")
        except Exception:
            print("Security warning: SQLite VACUUM after metadata migration failed.")

    def _migrate_sensitive_metadata(self, key: bytes) -> None:
        migration_performed = False
        with self.db.connect() as conn:
            conn.execute("PRAGMA secure_delete = ON;")
            org_rows = conn.execute(
                "SELECT id, name, encrypted_data, encrypted, metadata_encrypted_version FROM organizations"
            ).fetchall()
            for row in org_rows:
                if not self._needs_entity_metadata_migration(row):
                    continue
                encrypted_data = self._encrypt_entity_name(key, row["name"])
                conn.execute(
                    """
                    UPDATE organizations
                    SET encrypted_data=?, encrypted=1, metadata_encrypted_version=?, name=?, updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (encrypted_data, METADATA_ENCRYPTED_VERSION, self._opaque_name_token(), row["id"]),
                )
                migration_performed = True

            group_rows = conn.execute(
                "SELECT id, name, encrypted_data, encrypted, metadata_encrypted_version FROM groups"
            ).fetchall()
            for row in group_rows:
                if not self._needs_entity_metadata_migration(row):
                    continue
                encrypted_data = self._encrypt_entity_name(key, row["name"])
                conn.execute(
                    """
                    UPDATE groups
                    SET encrypted_data=?, encrypted=1, metadata_encrypted_version=?, name=?, updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (encrypted_data, METADATA_ENCRYPTED_VERSION, self._opaque_name_token(), row["id"]),
                )
                migration_performed = True

            device_rows = conn.execute(
                "SELECT id, name, encrypted_data, encrypted, metadata_encrypted_version FROM devices"
            ).fetchall()
            for row in device_rows:
                if not self._needs_entity_metadata_migration(row):
                    continue
                encrypted_data = self._encrypt_entity_name(key, row["name"])
                conn.execute(
                    """
                    UPDATE devices
                    SET encrypted_data=?, encrypted=1, metadata_encrypted_version=?, name=?, updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (encrypted_data, METADATA_ENCRYPTED_VERSION, self._opaque_name_token(), row["id"]),
                )
                migration_performed = True

            cred_rows = conn.execute(
                """
                SELECT id, title, type, environment, tags, encrypted_payload, encrypted, metadata_encrypted_version
                FROM credentials
                """
            ).fetchall()
            for row in cred_rows:
                if not self._needs_credential_metadata_migration(key, row):
                    continue
                title, cred_type, environment, tags, payload = self._decrypt_credential_record(key, row)
                encrypted_payload = self._encrypt_credential_record(key, title, cred_type, environment, tags, payload)
                conn.execute(
                    """
                    UPDATE credentials
                    SET encrypted_payload=?, title=?, type=?, environment=?, tags=?,
                        encrypted=1, metadata_encrypted_version=?, updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (
                        encrypted_payload,
                        self._opaque_name_token(),
                        self._opaque_metadata_placeholder(),
                        self._opaque_metadata_placeholder(),
                        self._opaque_metadata_placeholder(),
                        METADATA_ENCRYPTED_VERSION,
                        row["id"],
                    ),
                )
                migration_performed = True

            conn.commit()
            if migration_performed:
                self._cleanup_sqlite_after_migration(conn)

    def change_master_password(self, old_password: str, new_password: str) -> bytes | None:
        old_key = self.unlock(old_password)
        if not old_key:
            return None

        new_salt = self.crypto.generate_kdf_salt()
        new_hash = self.crypto.hash_master_password(new_password)
        new_kdf_name = self.crypto.DEFAULT_KDF_NAME
        new_kdf_version = self.crypto.DEFAULT_KDF_VERSION
        new_kdf_params = self.crypto.default_kdf_params()
        new_key = self.crypto.derive_fernet_key(new_password, new_salt, new_kdf_name, new_kdf_params)

        with self.db.connect() as conn:
            rows = conn.execute("SELECT id, encrypted_payload FROM credentials").fetchall()
            for row in rows:
                payload = self.crypto.decrypt_payload(old_key, row["encrypted_payload"])
                re_encrypted = self.crypto.encrypt_payload(new_key, payload)
                conn.execute(
                    "UPDATE credentials SET encrypted_payload=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (re_encrypted, row["id"]),
                )

            for table in ("organizations", "groups", "devices"):
                rows = conn.execute(f"SELECT id, encrypted_data FROM {table} WHERE encrypted_data IS NOT NULL").fetchall()
                for row in rows:
                    value = self.crypto.decrypt_payload(old_key, row["encrypted_data"])
                    encrypted_data = self.crypto.encrypt_payload(new_key, value)
                    conn.execute(
                        f"UPDATE {table} SET encrypted_data=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                        (encrypted_data, row["id"]),
                    )

            conn.execute(
                "UPDATE vault_meta SET password_hash=?, kdf_salt=?, kdf_name=?, kdf_version=?, kdf_params=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
                (new_hash, base64.b64encode(new_salt), new_kdf_name, new_kdf_version, json.dumps(new_kdf_params)),
            )
            conn.commit()

        self._session_key = new_key
        return new_key

    def clear_decrypted_cache(self) -> None:
        self.clear_session()

    def _require_session_key(self) -> bytes:
        if not self._session_key:
            raise RuntimeError("Vault is locked.")
        return self._session_key

    def add_organization(self, name: str) -> int:
        key = self._require_session_key()
        encrypted_data = self._encrypt_entity_name(key, name)
        return self.db.execute(
            "INSERT INTO organizations(name, encrypted_data, encrypted, metadata_encrypted_version) VALUES(?, ?, 1, ?)",
            (self._opaque_name_token(), encrypted_data, METADATA_ENCRYPTED_VERSION),
        )

    def add_group(self, organization_id: int, name: str, parent_group_id: int | None = None) -> int:
        key = self._require_session_key()
        encrypted_data = self._encrypt_entity_name(key, name)
        return self.db.execute(
            """
            INSERT INTO groups(organization_id, name, parent_group_id, encrypted_data, encrypted, metadata_encrypted_version)
            VALUES(?, ?, ?, ?, 1, ?)
            """,
            (organization_id, self._opaque_name_token(), parent_group_id, encrypted_data, METADATA_ENCRYPTED_VERSION),
        )

    def add_device(self, organization_id: int, group_id: int, name: str) -> int:
        key = self._require_session_key()
        encrypted_data = self._encrypt_entity_name(key, name)
        return self.db.execute(
            """
            INSERT INTO devices(organization_id, group_id, name, encrypted_data, encrypted, metadata_encrypted_version)
            VALUES(?, ?, ?, ?, 1, ?)
            """,
            (organization_id, group_id, self._opaque_name_token(), encrypted_data, METADATA_ENCRYPTED_VERSION),
        )

    def rename_organization(self, org_id: int, name: str) -> None:
        key = self._require_session_key()
        encrypted_data = self._encrypt_entity_name(key, name)
        self.db.execute(
            """
            UPDATE organizations
            SET name=?, encrypted_data=?, encrypted=1, metadata_encrypted_version=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (self._opaque_name_token(), encrypted_data, METADATA_ENCRYPTED_VERSION, org_id),
        )

    def rename_group(self, group_id: int, name: str) -> None:
        key = self._require_session_key()
        encrypted_data = self._encrypt_entity_name(key, name)
        self.db.execute(
            """
            UPDATE groups
            SET name=?, encrypted_data=?, encrypted=1, metadata_encrypted_version=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (self._opaque_name_token(), encrypted_data, METADATA_ENCRYPTED_VERSION, group_id),
        )

    def rename_device(self, device_id: int, name: str) -> None:
        key = self._require_session_key()
        encrypted_data = self._encrypt_entity_name(key, name)
        self.db.execute(
            """
            UPDATE devices
            SET name=?, encrypted_data=?, encrypted=1, metadata_encrypted_version=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (self._opaque_name_token(), encrypted_data, METADATA_ENCRYPTED_VERSION, device_id),
        )

    def update_device(self, device_id: int, organization_id: int, group_id: int, name: str) -> None:
        key = self._require_session_key()
        encrypted_data = self._encrypt_entity_name(key, name)
        self.db.execute(
            """
            UPDATE devices
            SET organization_id=?, group_id=?, name=?, encrypted_data=?, encrypted=1,
                metadata_encrypted_version=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (organization_id, group_id, self._opaque_name_token(), encrypted_data, METADATA_ENCRYPTED_VERSION, device_id),
        )

    def delete_organization(self, org_id: int) -> None:
        self.db.execute("DELETE FROM organizations WHERE id=?", (org_id,))

    def delete_group(self, group_id: int) -> None:
        self.db.execute("DELETE FROM groups WHERE id=?", (group_id,))

    def delete_device(self, device_id: int) -> None:
        self.db.execute("DELETE FROM devices WHERE id=?", (device_id,))

    def list_organizations(self) -> list[dict[str, Any]]:
        key = self._require_session_key()
        rows = self.db.fetchall("SELECT id, name, encrypted_data FROM organizations ORDER BY id")
        out = [
            {"id": r["id"], "name": self._decrypt_entity_name(key, r["encrypted_data"], r["name"])}
            for r in rows
        ]
        return sorted(out, key=lambda x: x["name"].lower())

    def list_groups(self, organization_id: int | None = None) -> list[dict[str, Any]]:
        key = self._require_session_key()
        if organization_id is None:
            rows = self.db.fetchall("SELECT id, organization_id, name, encrypted_data, parent_group_id FROM groups ORDER BY id")
        else:
            rows = self.db.fetchall(
                "SELECT id, organization_id, name, encrypted_data, parent_group_id FROM groups WHERE organization_id=? ORDER BY id",
                (organization_id,),
            )
        out = [
            {
                "id": r["id"],
                "organization_id": r["organization_id"],
                "name": self._decrypt_entity_name(key, r["encrypted_data"], r["name"]),
                "parent_group_id": r["parent_group_id"],
            }
            for r in rows
        ]
        return sorted(out, key=lambda x: x["name"].lower())

    def list_devices(self, group_id: int | None = None) -> list[dict[str, Any]]:
        key = self._require_session_key()
        if group_id is None:
            rows = self.db.fetchall("SELECT id, organization_id, group_id, name, encrypted_data FROM devices ORDER BY id")
        else:
            rows = self.db.fetchall(
                "SELECT id, organization_id, group_id, name, encrypted_data FROM devices WHERE group_id=? ORDER BY id",
                (group_id,),
            )
        out = [
            {
                "id": r["id"],
                "organization_id": r["organization_id"],
                "group_id": r["group_id"],
                "name": self._decrypt_entity_name(key, r["encrypted_data"], r["name"]),
            }
            for r in rows
        ]
        return sorted(out, key=lambda x: x["name"].lower())

    def add_credential(
        self,
        key: bytes,
        organization_id: int,
        group_id: int | None,
        device_id: int | None,
        title: str,
        cred_type: str,
        environment: str,
        tags: str,
        payload: dict[str, Any],
    ) -> int:
        encrypted = self._encrypt_credential_record(key, title, cred_type, environment, tags, payload)
        return self.db.execute(
            """
            INSERT INTO credentials(
              organization_id, group_id, device_id, title, type, environment, tags, encrypted_payload, encrypted, metadata_encrypted_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                organization_id,
                group_id,
                device_id,
                self._opaque_name_token(),
                self._opaque_metadata_placeholder(),
                self._opaque_metadata_placeholder(),
                self._opaque_metadata_placeholder(),
                encrypted,
                METADATA_ENCRYPTED_VERSION,
            ),
        )

    def update_credential(
        self,
        key: bytes,
        credential_id: int,
        organization_id: int,
        group_id: int | None,
        device_id: int | None,
        title: str,
        cred_type: str,
        environment: str,
        tags: str,
        payload: dict[str, Any],
    ) -> None:
        encrypted = self._encrypt_credential_record(key, title, cred_type, environment, tags, payload)
        self.db.execute(
            """
            UPDATE credentials
            SET organization_id=?, group_id=?, device_id=?, title=?, type=?, environment=?, tags=?,
                encrypted_payload=?, encrypted=1, metadata_encrypted_version=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (
                organization_id,
                group_id,
                device_id,
                self._opaque_name_token(),
                self._opaque_metadata_placeholder(),
                self._opaque_metadata_placeholder(),
                self._opaque_metadata_placeholder(),
                encrypted,
                METADATA_ENCRYPTED_VERSION,
                credential_id,
            ),
        )

    def delete_credential(self, credential_id: int) -> None:
        self.db.execute("DELETE FROM credentials WHERE id=?", (credential_id,))

    def load_credentials_decrypted(self, key: bytes) -> list[CredentialView]:
        rows = self.db.fetchall(
            """
            SELECT
                c.id, c.organization_id, o.name AS organization_name, o.encrypted_data AS organization_encrypted,
                c.group_id, g.name AS group_name, g.encrypted_data AS group_encrypted,
                c.device_id, d.name AS device_name, d.encrypted_data AS device_encrypted,
                c.title, c.type, c.environment, c.tags, c.encrypted_payload,
                c.created_at, c.updated_at
            FROM credentials c
            JOIN organizations o ON o.id = c.organization_id
            LEFT JOIN groups g ON g.id = c.group_id
            LEFT JOIN devices d ON d.id = c.device_id
            ORDER BY c.updated_at DESC
            """
        )
        out: list[CredentialView] = []
        for row in rows:
            title, cred_type, environment, tags, payload = self._decrypt_credential_record(key, row)
            out.append(
                CredentialView(
                    id=row["id"],
                    organization_id=row["organization_id"],
                    organization_name=self._decrypt_entity_name(key, row["organization_encrypted"], row["organization_name"]),
                    group_id=row["group_id"],
                    group_name=self._decrypt_entity_name(key, row["group_encrypted"], row["group_name"])
                    if row["group_id"] is not None
                    else None,
                    device_id=row["device_id"],
                    device_name=self._decrypt_entity_name(key, row["device_encrypted"], row["device_name"])
                    if row["device_id"] is not None
                    else None,
                    title=title,
                    cred_type=cred_type,
                    environment=environment,
                    tags=tags,
                    payload=payload,
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )
            )
        return out
