# Development

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Security checks

```powershell
python tools/security_check_db.py
python tools/smoke_security_test.py
```
