[English version](README.md)

# Local Password Vault

> Status: MVP / Prototype  
> Local-only encrypted password vault. Not audited. Not production-ready.

Local-first encrypted password vault.
Десктопний застосунок на Python і PyQt.
Призначений для персонального, development, внутрішнього та лабораторного використання.
Не є cloud-рішенням.
Не проходив професійний аудит безпеки.
Не є заміною аудитованих enterprise password manager-рішень.

## Огляд

Local Password Vault - це локальний encrypted password vault для збереження:

- організацій
- груп
- пристроїв
- облікових даних
- SSH-даних
- нотаток
- IP
- URL
- логіна
- пароля

Проєкт орієнтований на практичне локальне зберігання секретів для персональних і внутрішніх сценаріїв без завищених обіцянок щодо enterprise-рівня.

## Поточний статус

Це local-first encrypted password vault MVP.

- MVP / prototype
- локальний режим
- проєкт має фокус на безпеці, але не проходив професійний security audit
- підходить для персонального, dev, внутрішнього або лабораторного використання
- не рекомендується для критичних production secrets без незалежної перевірки безпеки

Проєкт не позиціонується як повноцінна заміна Bitwarden / 1Password / KeePassXC.

## Можливості

- Локальний encrypted vault
- Локальне зберігання в SQLite
- Шифрування credential payloads
- Шифрування metadata
- Master password
- Auto-lock після неактивності
- Автоочищення clipboard для скопійованих секретів
- Show/hide password controls
- Генератор паролів
- Попередження про повторне використання пароля
- Ієрархія organization / group / device
- Поля notes, IP, URL, login, password
- Підтримка SSH-related fields
- RAM-only search index
- Пошук по розшифрованих non-secret полях
- Secret-like fields не індексуються за замовчуванням
- Encrypted SQLite backup
- Local-only storage
- Security check tools
- Smoke/security test tools

## Модель безпеки

- Дані зберігаються локально в SQLite.
- Sensitive credential data шифрується.
- Metadata, наприклад назви organization/group/device/credential, шифрується там, де це можливо.
- Технічні ID і зв'язки лишаються plaintext, бо потрібні для структури БД.
- Розшифровані дані існують у RAM тільки під час unlocked-сесії.
- Search index будується в RAM після unlock.
- Search index за замовчуванням не включає secret-like fields:
  - password
  - private key
  - passphrase
  - token
  - API key
  - secrets
- Clipboard cleanup працює best-effort.
- SQLite secure_delete і VACUUM використовуються після migration там, де можливо.
- Python не гарантує ідеальне очищення пам'яті.

## Обмеження

- Немає професійного security audit.
- Немає cloud sync.
- Немає multi-user mode.
- Немає browser extension.
- Немає mobile app.
- Немає hardware key / 2FA.
- RAM cleanup - best-effort.
- Clipboard cleanup - best-effort.
- Якщо локальний комп'ютер скомпрометований, vault теж може бути скомпрометований.
- Filesystem snapshots, backups, OS cache, antivirus quarantine і recovery tools можуть зберігати артефакти поза контролем застосунку.
- Не рекомендується для критичних production secrets без незалежної security review.

## Встановлення

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

## Використання

- Створити master password.
- Розблокувати vault.
- Створити organizations, groups і devices.
- Додати credentials.
- Використовувати пошук.
- Копіювати паролі за потреби.
- Створювати encrypted database backups.
- Vault автоматично блокується після неактивності.

Примітки:

- password fields приховані за замовчуванням;
- reveal виконується тільки вручну користувачем;
- copied secrets автоматично очищаються з clipboard, коли це можливо.

### Приклади використання

Таблиця credentials з ієрархією та замаскованими паролями:

![Список credentials](usage-01-credentials-list.png)

Перегляд деталей пристрою з можливістю копіювання значень:

![Деталі пристрою](usage-02-device-details.png)

Форма створення/редагування credential:

![Форма credential](usage-03-credential-form.png)

## Перевірки безпеки

```bash
python -m compileall app main.py config.py tools
python tools/smoke_security_test.py
python tools/security_check_db.py
```

- compileall перевіряє синтаксис Python-файлів;
- smoke test створює тестовий vault;
- security check сканує SQLite database на plaintext test markers;
- ці тести корисні для development;
- ці тести не замінюють професійний security audit.

## Структура проєкту

```text
app/
app/ui/
app/assets/
tools/
data/
main.py
config.py
```

- app/ - основна логіка застосунку
- app/ui/ - PyQt UI
- app/assets/ - іконки та assets
- tools/ - smoke/security helper scripts
- data/ - локальна runtime database directory
- main.py - entry point
- config.py - базова конфігурація

## Документація

- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- [docs/SECURITY.md](docs/SECURITY.md)
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [docs/DISCLAIMER.md](docs/DISCLAIMER.md)
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)
- [docs/CHANGELOG.md](docs/CHANGELOG.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)

## Roadmap / План розвитку

Деталі: [docs/ROADMAP.md](docs/ROADMAP.md).

## Участь у розробці

Внески вітаються.

Зміни, що стосуються безпеки, потрібно перевіряти особливо уважно.

Не додавайте реальні secrets в issues, pull requests, screenshots, logs, test files або example databases.

Для security-related повідомлень використовуйте email з розділу контактів.

## Контакти

Для питань, відгуків або повідомлень щодо безпеки:

- Розробник: Anton Pobyvanets
- Email: antonpython3@gmail.com

## Ліцензія

Проєкт розповсюджується за MIT License.


