[English version](README.md)

# Local Infrastructure Vault

> Status: MVP / Prototype  
> Локальний encrypted infrastructure credentials vault. Не аудитований. Не production-ready.

Local Infrastructure Vault - це local-first encrypted desktop застосунок для обліку доступів до технічної інфраструктури: серверів, камер, edge-пристроїв, мережевого обладнання, баз даних, API, SSH, RTSP-потоків, admin panel і внутрішніх сервісів.

Доступи організовані через organizations, groups, devices і пов'язані записи.
Проєкт не є cloud-рішенням, не проходив професійний security audit і не є заміною аудитованих enterprise password manager-рішень.

## Огляд

Local Infrastructure Vault сфокусований на обліку інфраструктурних активів і доступів у технічних workflow.

Можна зберігати та організовувати:

- organizations / clients / environments
- groups / locations / projects
- devices / servers / services
- credentials
- IP addresses
- URLs / admin panels
- SSH-related data
- RTSP / API / service endpoints
- login / password pairs
- technical notes

### Для чого цей проєкт

- невеликі технічні команди
- R&D / лабораторії
- DevOps / системне адміністрування
- локальний облік доступів до інфраструктури
- камери / NVR / RTSP-проєкти
- edge AI пристрої
- тестові стенди
- внутрішні offline-first інструменти

### Чим цей проєкт НЕ є

Цей проєкт НЕ є:

- заміною для аудитованих enterprise password manager систем
- cloud password manager
- браузерним autofill-інструментом
- мобільним password manager
- secrets manager для production CI/CD
- enterprise zero-trust платформою

## Поточний статус

- MVP / prototype
- локальний режим
- фокус на безпеці, але без професійного security audit
- підходить для персональних, лабораторних, внутрішніх і development інфраструктурних workflow
- не рекомендується для критичних production secrets без незалежної security review

## Можливості

- Локальний encrypted infrastructure vault
- Локальне зберігання в SQLite
- Шифрування credential payloads
- Шифрування metadata
- Ієрархія organization / group / device
- Credentials, пов'язані з devices, services і технічними активами
- Підтримка IP, URL, login, password, SSH-related fields і notes
- Підходить для servers, cameras, routers, edge devices, lab machines, databases, APIs і internal services
- Master password protection
- Auto-lock після неактивності
- Автоочищення clipboard для скопійованих секретів
- Show/hide password controls
- Генератор паролів
- Попередження про повторне використання пароля
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
- Створити organization / client / environment.
- Створити group / location / project.
- Створити device / server / service.
- Додати credentials і технічні нотатки.
- Зберегти IP / URL / SSH / RTSP / API / admin panel інформацію.
- Шукати за non-secret технічними полями.
- Копіювати secrets за потреби.
- Створювати encrypted database backups.
- Vault автоматично блокується після неактивності.

Примітки:

- password fields приховані за замовчуванням;
- reveal виконується тільки вручну користувачем;
- copied secrets автоматично очищаються з clipboard, коли це можливо.

### Приклади використання

Таблиця infrastructure credentials з ієрархією organization/group/device:

![Список credentials](usage-01-credentials-list.png)

Деталі device або service з швидким копіюванням технічних полів:

![Деталі пристрою](usage-02-device-details.png)

Форма credential для server/device/service access даних:

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
