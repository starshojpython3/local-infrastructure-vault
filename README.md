[Українська версія](README_UA.md)

# Local Password Vault

> Status: MVP / Prototype  
> Local-only encrypted password vault. Not audited. Not production-ready.

Local-first encrypted password vault.
Desktop application built with Python and PyQt.
Designed for personal, development, internal, and lab usage.
Not cloud-based.
Not professionally audited.
Not a replacement for audited enterprise password managers.

## Overview

Local Password Vault is a local encrypted password vault for storing:

- organizations
- groups
- devices
- credentials
- SSH-related data
- notes
- IP
- URL
- login
- password

The project is focused on practical local secret management for personal and internal workflows, without claiming enterprise-grade audited security.

## Current Status

Local-first encrypted password vault MVP.

- MVP / prototype
- local-only
- security-focused, but not audited
- suitable for personal/internal experiments
- suitable for development and lab environments
- not recommended for highly critical production secrets without independent security review

## Features

- Local encrypted vault
- SQLite-based local storage
- Encrypted credential payloads
- Encrypted metadata
- Master password protection
- Auto-lock after inactivity
- Clipboard auto-clear for copied secrets
- Show/hide password controls
- Password generator
- Password reuse warning
- Organization / group / device hierarchy
- Credential notes, IP, URL, login, password fields
- SSH-related fields support
- RAM-only search index
- Search over decrypted non-secret fields
- Secret-like fields excluded from search index by default
- Encrypted SQLite backup
- Local-only storage
- Security check tools
- Smoke/security test tools

## Security Model

- Data is stored locally in SQLite.
- Sensitive credential data is encrypted.
- Metadata such as organization/group/device/credential names is encrypted where possible.
- Technical IDs and relationships remain plaintext because they are required for database structure.
- Decrypted data exists in RAM only during an unlocked session.
- Search index is built in RAM after unlock.
- Search index excludes secret-like fields by default:
  - password
  - private key
  - passphrase
  - token
  - API key
  - secrets
- Clipboard cleanup is best-effort.
- SQLite secure_delete and VACUUM are used after migration where possible.
- Python cannot guarantee perfect memory wiping.

## Limitations

- No professional security audit.
- No cloud sync.
- No multi-user mode yet.
- No browser extension.
- No mobile app.
- No hardware key / 2FA yet.
- RAM cleanup is best-effort.
- Clipboard cleanup is best-effort.
- If the local machine is compromised, vault security can be compromised.
- Filesystem snapshots, backups, OS cache, antivirus quarantine, and recovery tools may retain artifacts outside application control.
- Not recommended for highly critical production secrets without independent review.

## Installation

```bash
git clone <repo-url>
cd password_vault
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Linux/macOS:

```bash
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Usage

- Create a master password.
- Unlock the vault.
- Create organizations, groups, and devices.
- Add credentials.
- Use search.
- Copy passwords when needed.
- Create encrypted database backups.
- Vault auto-locks after inactivity.

Notes:

- password fields are hidden by default;
- reveal is controlled manually by user;
- copied secrets are cleared from clipboard automatically when possible.

### Usage Examples

Credentials table with hierarchy and masked passwords:

![Credentials list](usage-01-credentials-list.png)

Device details view with quick copyable fields:

![Device details](usage-02-device-details.png)

Credential create/edit form:

![Credential form](usage-03-credential-form.png)

## Security Checks

```bash
python -m compileall app main.py config.py tools
python tools/smoke_security_test.py
python tools/security_check_db.py
```

- compileall checks Python syntax;
- smoke test creates a test vault;
- security check scans the SQLite database for plaintext test markers;
- these checks are useful for development;
- these checks are not a replacement for professional security audit.

## Project Structure

```text
app/
app/ui/
app/assets/
tools/
data/
main.py
config.py
```

- app/ - core application logic
- app/ui/ - PyQt UI
- app/assets/ - icons and assets
- tools/ - smoke/security helper scripts
- data/ - local runtime database directory
- main.py - application entry point
- config.py - basic configuration

## Documentation

- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- [docs/SECURITY.md](docs/SECURITY.md)
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [docs/DISCLAIMER.md](docs/DISCLAIMER.md)
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)
- [docs/CHANGELOG.md](docs/CHANGELOG.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing

Contributions are welcome.

Security-related changes should be reviewed carefully.

Please do not submit real secrets in issues, pull requests, screenshots, logs, test files, or example databases.

For security-related reports, use the contact email below.

## Contact

For questions, feedback, or security-related reports, contact:

- Developer: Anton Pobyvanets
- Email: antonpython3@gmail.com

## License

This project is released under the MIT License.


