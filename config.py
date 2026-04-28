import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "vault.db"

APP_NAME = "Password Vault"
APP_VERSION = "0.1.0"
CLIPBOARD_CLEAR_MS = 30_000
AUTO_LOCK_TIMEOUT_MS = 10 * 60 * 1000

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

KDF_ITERATIONS = 390_000
KDF_SALT_LEN = 16
