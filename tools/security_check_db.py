from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "vault.db"

MARKERS = [
    "PLAIN_ORG_SHOULD_NOT_EXIST",
    "PLAIN_GROUP_SHOULD_NOT_EXIST",
    "PLAIN_DEVICE_SHOULD_NOT_EXIST",
    "PLAIN_CRED_SHOULD_NOT_EXIST",
    "PLAIN_LOGIN_SHOULD_NOT_EXIST",
    "PLAIN_PASSWORD_SHOULD_NOT_EXIST",
    "PLAIN_NOTES_SHOULD_NOT_EXIST",
]

TABLE_CHECKS: dict[str, tuple[str, ...]] = {
    "organizations": ("name",),
    "groups": ("name",),
    "devices": ("name",),
    "credentials": ("title", "type", "environment", "tags"),
}


def is_opaque_value(value: str) -> bool:
    text = (value or "").strip()
    return text == "" or text == "__encrypted__" or text.startswith("enc_")


def run_security_check(db_path: Path = DB_PATH) -> tuple[bool, list[str]]:
    report: list[str] = []
    failed = False

    if not db_path.exists():
        return False, [f"FAIL: DB file not found: {db_path}"]

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        for table, fields in TABLE_CHECKS.items():
            columns = ", ".join(fields)
            rows = conn.execute(f"SELECT id, {columns} FROM {table}").fetchall()
            table_failures = 0
            for row in rows:
                for field in fields:
                    value = str(row[field] or "")
                    if not is_opaque_value(value):
                        table_failures += 1
            if table_failures:
                failed = True
                report.append(f"FAIL: {table} plaintext-like rows detected: {table_failures}")
            else:
                report.append(f"OK: {table} metadata fields look opaque")

    raw = db_path.read_bytes()
    marker_hits: list[str] = []
    for marker in MARKERS:
        if marker.encode("utf-8") in raw:
            marker_hits.append(marker)

    if marker_hits:
        failed = True
        report.append(f"FAIL: binary marker scan hits: {', '.join(marker_hits)}")
    else:
        report.append("OK: binary marker scan")

    return (not failed), report


def main() -> int:
    ok, report = run_security_check(DB_PATH)
    print(f"DB path: {DB_PATH}")
    for line in report:
        print(line)
    print(f"Result: {'OK' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
