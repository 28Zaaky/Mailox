# Contributing

Thanks for helping. Security issues do not go here: see [SECURITY.md](SECURITY.md).

## Development setup

Follow the [manual install](README.md#manual-install) in the README (PostgreSQL, Redis,
`setup-selfhosted.sh` / `.ps1`), then install the test dependencies:

```bash
cd backend && pip install -r requirements-dev.txt
```

Create the test database once: `CREATE DATABASE mailox_test OWNER mailox;`.

## Before opening a pull request

All checks must pass, and the backend suite must pass **under both editions**
(routes and access rules differ between them):

```bash
cd backend
MAILOX_EDITION=selfhosted python -m pytest
MAILOX_EDITION=saas python -m pytest

cd ../frontend
npx tsc -b --noEmit
npm run lint
npm test
npm run build
```

## Code style

- Python 3.12, line length 100 (`ruff` settings in `backend/pyproject.toml`). Type
  hints on new code; async SQLAlchemy in the API, keep blocking I/O out of request
  handlers.
- Database changes go through a new Alembic migration in `backend/alembic/versions/`,
  never by editing an existing one.
- New settings go in `backend/app/core/config.py` with a safe default (offensive
  features off, restrictive behaviour when unset) and in the configuration table of
  the README.
- TypeScript must type-check cleanly (`tsc -b`) and `oxlint` must report no errors.
  React function components, API calls through
  `frontend/src/lib/api.ts` (relative `/api/v1`).
- Tests for every behaviour change, including the negative case for anything that
  touches authentication, tenant isolation or the scan egress guards.

## Tests must never touch third-party infrastructure

Never add a test that scans, resolves, connects to or emails a real domain you do not
own. Use `example.com` / `example.org` / `example.net` (RFC 2606) or the `.test` TLD,
and mock DNS, SMTP and HTTP. The test suite must run offline apart from the local
PostgreSQL and Redis.

## Pull request flow

1. Fork, branch from `main` (`fix/...`, `feat/...`).
2. Keep the change focused; describe what and why in the PR, and how you tested it.
3. CI and review, then squash-merge. No CLA or DCO sign-off required: by submitting a
   contribution you agree it is licensed under the repository's [MIT licence](LICENSE).
