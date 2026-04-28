from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import config


class Database:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or config.DB_PATH

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            try:
                mode_row = conn.execute("PRAGMA journal_mode;").fetchone()
                current_mode = str(mode_row[0]).lower() if mode_row else ""
                if current_mode == "wal":
                    conn.execute("PRAGMA journal_mode=DELETE;")
            except Exception:
                pass
            conn.executescript(
                """
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS vault_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    password_hash TEXT NOT NULL,
                    kdf_salt BLOB NOT NULL,
                    kdf_name TEXT NOT NULL DEFAULT 'pbkdf2_sha256',
                    kdf_version INTEGER NOT NULL DEFAULT 1,
                    kdf_params TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS organizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    encrypted_data BLOB,
                    encrypted INTEGER NOT NULL DEFAULT 0,
                    metadata_encrypted_version INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    encrypted_data BLOB,
                    encrypted INTEGER NOT NULL DEFAULT 0,
                    metadata_encrypted_version INTEGER NOT NULL DEFAULT 0,
                    parent_group_id INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY (parent_group_id) REFERENCES groups(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id INTEGER NOT NULL,
                    group_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    encrypted_data BLOB,
                    encrypted INTEGER NOT NULL DEFAULT 0,
                    metadata_encrypted_version INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id INTEGER NOT NULL,
                    group_id INTEGER,
                    device_id INTEGER,
                    title TEXT NOT NULL,
                    type TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    tags TEXT NOT NULL DEFAULT '',
                    encrypted_payload BLOB NOT NULL,
                    encrypted INTEGER NOT NULL DEFAULT 1,
                    metadata_encrypted_version INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
                );
                """
            )
            self._ensure_column(conn, "organizations", "encrypted_data", "BLOB")
            self._ensure_column(conn, "organizations", "encrypted", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "organizations", "metadata_encrypted_version", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "groups", "encrypted_data", "BLOB")
            self._ensure_column(conn, "groups", "encrypted", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "groups", "metadata_encrypted_version", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "devices", "encrypted_data", "BLOB")
            self._ensure_column(conn, "devices", "encrypted", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "devices", "metadata_encrypted_version", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "credentials", "encrypted", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column(conn, "credentials", "metadata_encrypted_version", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "vault_meta", "kdf_name", "TEXT NOT NULL DEFAULT 'pbkdf2_sha256'")
            self._ensure_column(conn, "vault_meta", "kdf_version", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column(conn, "vault_meta", "kdf_params", "TEXT")

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
        existing = {row["name"] for row in cols}
        if column in existing:
            return
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA secure_delete = ON;")
        return conn

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> int:
        with self.connect() as conn:
            cur = conn.execute(query, params)
            conn.commit()
            return cur.lastrowid

    def fetchone(self, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(query, params).fetchone()

    def fetchall(self, query: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return list(conn.execute(query, params).fetchall())
