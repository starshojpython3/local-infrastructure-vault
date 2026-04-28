from __future__ import annotations

import json
import os
from pathlib import Path

from PyQt6.QtWidgets import QFileDialog, QMessageBox

APP_DIR_NAME = "PasswordVault"
CONFIG_FILE_NAME = "settings.json"


def _settings_path() -> Path:
    local_app_data = os.getenv("LOCALAPPDATA")
    if local_app_data:
        base = Path(local_app_data) / APP_DIR_NAME
    else:
        base = Path.home() / ".password_vault"
    base.mkdir(parents=True, exist_ok=True)
    return base / CONFIG_FILE_NAME


def _load_settings() -> dict:
    path = _settings_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_settings(data: dict) -> None:
    path = _settings_path()
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _is_writable_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def resolve_storage_root() -> Path | None:
    settings = _load_settings()
    existing = settings.get("storage_root")
    if existing:
        root = Path(existing).expanduser()
        if _is_writable_dir(root):
            return root

    QMessageBox.information(
        None,
        "Storage Setup",
        "Choose storage folder for vault data and app files.\n"
        "This folder will contain your local database and backups.",
    )
    selected = QFileDialog.getExistingDirectory(
        None,
        "Choose Storage Folder",
        str(Path.home()),
        QFileDialog.Option.ShowDirsOnly,
    )
    if not selected:
        return None

    root = Path(selected)
    if not _is_writable_dir(root):
        QMessageBox.critical(
            None,
            "Storage Error",
            "Selected folder is not writable. Please choose another folder.",
        )
        return None

    _save_settings({"storage_root": str(root)})
    return root

