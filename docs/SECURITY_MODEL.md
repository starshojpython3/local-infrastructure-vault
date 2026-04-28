# Security Model

## Scope

This project is designed as a local-only password vault MVP.

## Core Model

- Local-only storage.
- Master password is not stored directly.
- Argon2 is used for password hashing / key derivation.
- Credential payload is encrypted.
- Database file must not be committed.
- No cloud sync.
- No team sharing.
- No recovery if master password is lost.

## Practical Notes

- Security depends on local machine integrity and OS account security.
- Backups should be handled carefully and stored securely.
- This project is not professionally audited.
