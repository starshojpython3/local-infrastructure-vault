from __future__ import annotations

import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.database import Database
from app.search_service import SearchService
from app.vault_service import VaultService
from tools.security_check_db import run_security_check

DB_PATH = ROOT_DIR / "data" / "vault.db"
MASTER_PASSWORD = "SmokeMasterPass_123!"

PLAIN_ORG = "PLAIN_ORG_SHOULD_NOT_EXIST"
PLAIN_GROUP = "PLAIN_GROUP_SHOULD_NOT_EXIST"
PLAIN_DEVICE = "PLAIN_DEVICE_SHOULD_NOT_EXIST"
PLAIN_CRED = "PLAIN_CRED_SHOULD_NOT_EXIST"
PLAIN_LOGIN = "PLAIN_LOGIN_SHOULD_NOT_EXIST"
PLAIN_PASSWORD = "PLAIN_PASSWORD_SHOULD_NOT_EXIST"
PLAIN_NOTES = "PLAIN_NOTES_SHOULD_NOT_EXIST"
PLAIN_TYPE = "PLAIN_TYPE_SHOULD_NOT_EXIST"
PLAIN_ENV = "PLAIN_ENV_SHOULD_NOT_EXIST"
PLAIN_TAG = "PLAIN_TAG_SHOULD_NOT_EXIST"
PLAIN_PRIVATE_KEY = "PLAIN_PRIVATE_KEY_SHOULD_NOT_EXIST"
PLAIN_SSH_PASSPHRASE = "PLAIN_SSH_PASSPHRASE_SHOULD_NOT_EXIST"


def backup_and_reset_db(db_path: Path) -> tuple[bool, Path | None]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if not db_path.exists():
        return True, None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = db_path.with_name(f"vault_before_security_fix_{ts}.db")
    try:
        shutil.move(str(db_path), str(backup))
        return True, backup
    except Exception:
        return False, None


def main() -> int:
    result = {
        "vault created": False,
        "CRUD": False,
        "decrypt read": False,
        "search non-secret": False,
        "search secret fields excluded": False,
        "plaintext DB scan": False,
        "backup": False,
        "repeat migration skipped": False,
    }

    backup_ok, backup_path = backup_and_reset_db(DB_PATH)
    result["backup"] = backup_ok

    db = Database(DB_PATH)
    db.initialize()
    service = VaultService(db)

    service.initialize_vault(MASTER_PASSWORD)
    key = service.unlock(MASTER_PASSWORD)
    if not key:
        print("vault created: FAIL")
        return 1
    result["vault created"] = True

    org_id = service.add_organization(PLAIN_ORG)
    group_id = service.add_group(org_id, PLAIN_GROUP)
    device_id = service.add_device(org_id, group_id, PLAIN_DEVICE)

    payload = {
        "username": PLAIN_LOGIN,
        "password": PLAIN_PASSWORD,
        "notes": PLAIN_NOTES,
        "ssh_private_key": PLAIN_PRIVATE_KEY,
        "ssh_passphrase": PLAIN_SSH_PASSPHRASE,
    }
    cred_id = service.add_credential(
        key,
        org_id,
        group_id,
        device_id,
        PLAIN_CRED,
        PLAIN_TYPE,
        PLAIN_ENV,
        PLAIN_TAG,
        payload,
    )

    service.update_credential(
        key,
        cred_id,
        org_id,
        group_id,
        device_id,
        PLAIN_CRED,
        PLAIN_TYPE,
        PLAIN_ENV,
        PLAIN_TAG,
        payload,
    )
    result["CRUD"] = True

    credentials = service.load_credentials_decrypted(key)
    selected = next((c for c in credentials if c.id == cred_id), None)
    if selected and selected.title == PLAIN_CRED and str(selected.payload.get("password", "")) == PLAIN_PASSWORD:
        result["decrypt read"] = True

    search = SearchService()
    non_secret_hits = search.filter_credentials(credentials, PLAIN_CRED)
    result["search non-secret"] = any(c.id == cred_id for c in non_secret_hits)

    secret_hits = search.filter_credentials(credentials, PLAIN_PASSWORD)
    pk_hits = search.filter_credentials(credentials, PLAIN_PRIVATE_KEY)
    phrase_hits = search.filter_credentials(credentials, PLAIN_SSH_PASSPHRASE)
    result["search secret fields excluded"] = not secret_hits and not pk_hits and not phrase_hits

    service.clear_session()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            UPDATE credentials
            SET title=?, type=?, environment=?, tags=?, metadata_encrypted_version=0, encrypted=1
            WHERE id=?
            """,
            (PLAIN_CRED, PLAIN_TYPE, PLAIN_ENV, PLAIN_TAG, cred_id),
        )
        before_unlock = conn.execute("SELECT updated_at FROM credentials WHERE id=?", (cred_id,)).fetchone()[0]
        conn.commit()

    key1 = service.unlock(MASTER_PASSWORD)
    if key1:
        with sqlite3.connect(DB_PATH) as conn:
            first_row = conn.execute(
                """
                SELECT updated_at, metadata_encrypted_version, title, type, environment, tags, hex(encrypted_payload)
                FROM credentials
                WHERE id=?
                """,
                (cred_id,),
            ).fetchone()
    else:
        first_row = None

    service.clear_session()
    key2 = service.unlock(MASTER_PASSWORD)
    if key2:
        with sqlite3.connect(DB_PATH) as conn:
            second_row = conn.execute(
                """
                SELECT updated_at, metadata_encrypted_version, title, type, environment, tags, hex(encrypted_payload)
                FROM credentials
                WHERE id=?
                """,
                (cred_id,),
            ).fetchone()
    else:
        second_row = None

    migrated_on_first = bool(first_row) and (
        int(first_row[1] or 0) == 2
        and str(first_row[2] or "").startswith("enc_")
        and str(first_row[3] or "") == "__encrypted__"
        and str(first_row[4] or "") == "__encrypted__"
        and str(first_row[5] or "") == "__encrypted__"
    )
    unchanged_on_second = bool(first_row and second_row) and first_row == second_row
    result["repeat migration skipped"] = migrated_on_first and unchanged_on_second

    db_ok, _report = run_security_check(DB_PATH)
    result["plaintext DB scan"] = db_ok

    print(f"vault created: {'OK' if result['vault created'] else 'FAIL'}")
    print(f"CRUD: {'OK' if result['CRUD'] else 'FAIL'}")
    print(f"decrypt read: {'OK' if result['decrypt read'] else 'FAIL'}")
    print(f"search non-secret: {'OK' if result['search non-secret'] else 'FAIL'}")
    print(f"search secret fields excluded: {'OK' if result['search secret fields excluded'] else 'FAIL'}")
    print(f"plaintext DB scan: {'OK' if result['plaintext DB scan'] else 'FAIL'}")
    print(f"backup: {'OK' if result['backup'] else 'FAIL'}")
    if backup_path:
        print(f"backup file: {backup_path}")
    print(f"repeat migration skipped: {'OK' if result['repeat migration skipped'] else 'FAIL'}")

    ok = all(result.values())
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
