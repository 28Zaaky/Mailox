<div align="center">
  <img src="https://mailox.khaotic.fr/apple-touch-icon.png" alt="MAILOX" width="180" />
  <h1>MAILOX</h1>
  <p>Automated security assessment for the email and web attack surface of a domain, from DNS authentication to active exploitation probes. Built by <a href="https://github.com/28Zaaky/">@28Zaaky</a>.</p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
  [![Website](https://img.shields.io/badge/Website-mailox.khaotic.fr-0a0a0a)](https://mailox.khaotic.fr)
  [![Docs](https://img.shields.io/badge/Docs-mailox.khaotic.fr%2Fdocs-blue)](https://mailox.khaotic.fr/docs)
</div>

---

<img width="1600" alt="MAILOX dashboard overview" src="https://mailox.khaotic.fr/screens/overview-1600.webp" />

---

See the [documentation](https://mailox.khaotic.fr/docs) for full setup and configuration.

---

> [!WARNING]
> Only scan infrastructure you own or have written authorisation to test. Scans run from your IP — no domain verification is enforced. Active modules are on by default; set them to `false` in `.env` if needed. Unauthorised use may be illegal (art. 323-1 Code pénal, US CFAA). Provided "as is" — see [LICENSE](LICENSE).

## What it checks

| Engine | Checks |
|---|---|
| DNS auth | SPF, DKIM (multiple selectors), DMARC, MTA-STS, TLS-RPT, BIMI |
| SMTP | MX discovery, STARTTLS, certificates, open relay, spoofing (canary) |
| Webmail | Exposed panels, TLS grade, login page fingerprint |
| CVE intel | NVD, CISA KEV, OSV against detected service versions |
| Web pentest | Active injection probes — SQLi, XSS, header injection (opt-in) |
| Cred probes | SMTP/IMAP default-credential attempts, rate-limited (opt-in) |
| Secrets | Pattern scan of uploaded archives |

## Install

### Docker (recommended)

Requires [Docker](https://docs.docker.com/get-docker/) with Compose v2.

```bash
git clone https://github.com/28Zaaky/Mailox.git mailox
cd mailox
./start.sh          # Linux / macOS
.\start.ps1         # Windows (PowerShell)
```

First run writes `.env` and `backend/.env.docker` with fresh secrets, runs migrations, and opens `http://localhost:8080`. Then create the admin account:

```bash
docker compose exec api python -m app.cli create-admin you@example.com
```

Day-to-day:

```bash
./start.sh stop              # stop (data stays in Docker volumes)
./start.sh logs              # follow logs
MAILOX_PORT=9090 ./start.sh  # custom port
```

### Manual install

Requires Python 3.12+, Node.js 20+, PostgreSQL 14+, Redis 7+.

```sql
-- as a PostgreSQL superuser
CREATE ROLE mailox LOGIN PASSWORD 'mailox';
CREATE DATABASE mailox OWNER mailox;
```

```bash
./setup-selfhosted.sh      # Linux / macOS
.\setup-selfhosted.ps1     # Windows (PowerShell)
```

Copies `backend/.env.selfhosted` to `backend/.env` with fresh secrets, runs migrations, installs frontend dependencies.

Start each process in its own terminal:

```bash
cd backend && . venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000   # API
celery -A app.worker.celery_app worker --loglevel=info  # worker
celery -A app.worker.celery_app beat --loglevel=info    # scheduler
cd frontend && npm run dev                              # UI → http://localhost:5173
```

Windows worker: add `--pool=solo`.

## Sign-in

**Local session** (manual install, `LOCAL_SESSION_ENABLED=true`): `POST /auth/local-session` opens a platform-admin workspace without credentials. The route only answers loopback peers; the Vite proxy is transparent to it. No login needed out of the box.

**Accounts mode** (`LOCAL_SESSION_ENABLED=false`, always with Docker): standard login with optional MFA. First registration becomes platform admin and must come from loopback, or use:

```bash
python -m app.cli create-admin you@example.com
# docker: docker compose exec api python -m app.cli create-admin you@example.com
```

Other CLI commands: `python -m app.cli --help`.

## Security notes

- Keep everything on `127.0.0.1`: uvicorn, Compose port bindings, PostgreSQL, Redis.
- Never run `vite --host` or bind uvicorn to `0.0.0.0`: anyone who reaches them reaches the API.
- To expose an instance: reverse proxy with TLS, `LOCAL_SESSION_ENABLED=false`, `ALLOWED_HOSTS`/`ALLOWED_ORIGINS` set to the real hostname, `TRUSTED_PROXY_COUNT` set to the number of proxies that append `X-Forwarded-For`.
- `MASTER_ENCRYPTION_KEY` encrypts stored secrets (MFA seeds, API keys). Losing it makes them unrecoverable; leaking it exposes them. Both `backend/.env` and `backend/.env.docker` are git-ignored.
- Outbound TCP 25 is required for SMTP checks. Blocked by most home ISPs and cloud providers — MAILOX reports *SMTP checks inconclusive* (SMTP-00) rather than failing silently.

## Configuration reference

Settings are read from `backend/.env` (manual) or `backend/.env.docker` (Docker). Unknown keys are ignored. Full list: `backend/app/core/config.py`.

| Variable | Default | Purpose |
|---|---|---|
| `MAILOX_EDITION` | `saas` | Set `selfhosted` for this repository. Both install paths do it automatically. |
| `LOCAL_SESSION_ENABLED` | `false` | No-login local session (loopback only). `true` in `.env.selfhosted`. |
| `SECRET_KEY`, `REFRESH_SECRET_KEY`, `MASTER_ENCRYPTION_KEY` | required | Three distinct keys, ≥ 32 chars. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` / `DATABASE_URL_SYNC` | required | `postgresql+asyncpg://...` / `postgresql+psycopg2://...` |
| `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | required | Redis URLs. |
| `ALLOWED_HOSTS` | `*` | Accepted `Host` headers. Pinned to `localhost,127.0.0.1` by install scripts. |
| `ALLOWED_ORIGINS` | empty | CORS origins, comma-separated. Required in production. |
| `TRUSTED_PROXY_COUNT` | `0` | Reverse proxies that append `X-Forwarded-For`. |
| `FRONTEND_URL` | `http://localhost:5173` | Used in emailed links. |
| `WEB_ACTIVE_PROBE_ENABLED` | `true` (selfhosted) | Active web injection probes. Authorisation required. |
| `CRED_PROBE_ENABLED` | `true` (selfhosted) | SMTP/IMAP credential probes. Rate-limited, capped. Authorisation required. |
| `CANARY_EMAIL` | unset | Address you control; enables open-relay and spoofing probes. |
| `NVD_API_KEY`, `GITHUB_TOKEN`, `INTELX_API_KEY` | unset | Optional intelligence sources. |
| `SMTP_HOST` … `SMTP_USE_TLS` | unset | Outgoing mail for password reset and invites. Without `SMTP_HOST`, emails are written to the API log. |
| `WORKER_CONCURRENCY` | `4` | Concurrent scans per worker. |
| `SCAN_TASK_TIMEOUT_SECONDS` | `120` | Per-scan timeout. |

## Running the tests

Create the test database once:

```sql
CREATE DATABASE mailox_test OWNER mailox;
```

Backend (needs PostgreSQL and Redis on localhost):

```bash
cd backend
pip install -r requirements-dev.txt
MAILOX_EDITION=selfhosted python -m pytest
MAILOX_EDITION=saas     python -m pytest
```

PowerShell: `$env:MAILOX_EDITION="selfhosted"; python -m pytest`

Frontend:

```bash
cd frontend
npx tsc -b --noEmit && npm run lint && npm test && npm run build
```

## Contributing, security, licence

- Contributions: [CONTRIBUTING.md](CONTRIBUTING.md)
- Vulnerabilities: report privately — [SECURITY.md](SECURITY.md). No public issues for security bugs.
- Bugs / features: [GitHub issues](https://github.com/28Zaaky/Mailox/issues)
- Licence: [MIT](LICENSE) — Copyright © 2026 Khaøtic Security
