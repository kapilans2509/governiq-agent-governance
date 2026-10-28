# GovernIQ — Agent Governance MVP

A Streamlit governance console plus a FastAPI HTTP gateway. Requests are evaluated against an explicit policy before registered **simulated** tools run.

## Run on Windows PowerShell
Do not recreate `.venv` while it is active. If it already exists:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```
Open the local URL shown by Streamlit.

## Start API in a second terminal
```powershell
.\.venv\Scripts\python.exe -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload
```
Docs: `http://127.0.0.1:8000/docs` | Health: `/health` | Evaluate: `POST /evaluate` | Audit verification: `/audit/verify`

Example JSON:
```json
{"tool":"search_policy","input":"Find policies about least privilege","mode":"Standard","session_id":"demo"}
```

## Tests
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Important limitations
This is a local MVP, not a production security guarantee. Tools are simulated. Threat detection uses patterns and can miss attacks. The SQLite hash chain detects edits but is not immutable against an administrator who can rewrite the database. API session IDs are attribution only; distributed per-agent rate limiting is not implemented. Before remote deployment, add strong identity and authorization, API-key/SSO controls, TLS, persistent per-agent limits, reviewed least-privilege adapters, centralized append-only logs, monitoring, backups, red-team tests and an independent security review. Set `GOVERNIQ_API_KEY` before exposing the API; the default server binds to localhost.
