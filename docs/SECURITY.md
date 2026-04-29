# Security Policy

## Current Security Status

This project is a local-first infrastructure credentials vault prototype for desktop use.

- It has not undergone a professional third-party security audit.
- It is not recommended for storing critical production credentials.
- Metadata encryption migration is versioned (`metadata_encrypted_version=2`) and runs once per legacy row; repeated unlocks skip already-migrated rows.
- New organization/group/device/credential writes store metadata encrypted immediately and keep SQLite plaintext metadata fields opaque (`enc_*` or `__encrypted__`).
- Technical linkage fields remain plaintext (for example IDs and parent/foreign-key references) so hierarchy and relations can work.
- Secrets in UI are masked by default in table, details panel, and editors; plaintext reveal is explicit via Show/Hide controls.
- Editor private key/password/passphrase fields are forced hidden on selection change, refresh, save/cancel, and lock flows; reveal is explicit.
- Copy-all action now requires confirmation before copying secret-bearing content to clipboard.
- Clipboard cleanup verifies vault-owned fingerprint/value before clearing, so user-overwritten clipboard content is not wiped.
- RAM search index excludes secret-like fields by default (password, private key, passphrase, token, secret, api key, and similar names).
- SQLite migration cleanup is best-effort and only after real migration changes: `PRAGMA secure_delete=ON`, `wal_checkpoint(TRUNCATE)`, `journal_mode=DELETE`, `VACUUM`.
- Added DB plaintext security check tool (`tools/security_check_db.py`) with table-field checks and binary marker scan for common plaintext test markers.
- Encrypted backup uses SQLite Backup API (transaction-consistent encrypted `.db` snapshot), not raw file copy.
- Master-password verification uses Argon2, while encryption-key derivation remains PBKDF2 with versioned KDF metadata (`kdf_name`, `kdf_version`, `kdf_params`, `kdf_salt`) to support safe future migration to Argon2id.
- Encryption keys and decrypted data can be present in RAM during an active unlocked session.
- Auto-lock performs best-effort cleanup for keys, decrypted caches, search index, dialogs, and clipboard.
- Python cannot guarantee complete secure memory wiping of all secret material.
- SQLite/OS/storage caches can still retain recoverable artifacts depending on filesystem, snapshots, backups, or crash timing.
- The user is responsible for backup handling, endpoint/device hardening, and physical access security.

## Reporting

If you find a security issue, open a private report to the maintainer before publishing details publicly.

