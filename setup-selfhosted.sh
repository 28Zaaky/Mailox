#!/usr/bin/env bash
# MAILOX self-hosted setup, manual path (Linux / macOS).
# Run from the repository root: ./setup-selfhosted.sh
# Requires Python 3.12+, Node.js 20+, a running PostgreSQL with the mailox role and
# database (see README.md), and Redis for the worker.

set -euo pipefail
cd "$(dirname "$0")"

echo "================================"
echo "MAILOX self-hosted setup"
echo "================================"
echo

# Requirements
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then PYTHON="$candidate"; break; fi
done
[ -n "$PYTHON" ] || { echo "Python 3.12+ is required but was not found."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "npm (Node.js 20+) is required but was not found."; exit 1; }
if ! command -v redis-cli >/dev/null 2>&1; then
    echo "Warning: redis-cli not found. Redis must be running on localhost:6379 before you start the worker."
elif ! redis-cli ping >/dev/null 2>&1; then
    echo "Warning: Redis does not answer on localhost:6379. Start it before you start the worker."
fi

# [1/4] Backend
echo "[1/4] Setting up backend..."
cd backend

if [ ! -d "venv" ]; then
    "$PYTHON" -m venv venv
fi
if [ -f venv/bin/activate ]; then
    # shellcheck disable=SC1091
    . venv/bin/activate
else
    # shellcheck disable=SC1091
    . venv/Scripts/activate   # Git Bash on Windows
fi
python -m pip install -q -r requirements.txt

if [ ! -f ".env" ]; then
    cp .env.selfhosted .env

    SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
    REFRESH_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
    MASTER_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

    # -i.bak works with both GNU sed (Linux) and BSD sed (macOS)
    sed -i.bak \
        -e "s/CHANGEME_generate_with_command_above_1111111111111111/${SECRET_KEY}/" \
        -e "s/CHANGEME_generate_with_command_above_2222222222222222/${REFRESH_KEY}/" \
        -e "s/CHANGEME_generate_with_command_above_3333333333333333/${MASTER_KEY}/" \
        .env && rm -f .env.bak

    if grep -q "CHANGEME_" .env; then
        echo "Key generation failed: placeholders remain in backend/.env, setup aborted."
        exit 1
    fi
    echo "   Generated secure keys in backend/.env"
else
    echo "   backend/.env already exists, skipping"
fi

# [2/4] Database migrations
echo "[2/4] Running database migrations..."
if ! python -m alembic upgrade head; then
    echo "Database migrations failed, setup aborted."
    echo "   Create the role and database first (as a PostgreSQL superuser):"
    echo "     psql -U postgres -c \"CREATE ROLE mailox LOGIN PASSWORD 'mailox';\""
    echo "     psql -U postgres -c \"CREATE DATABASE mailox OWNER mailox;\""
    echo "   then run this script again."
    exit 1
fi

cd ..

# [3/4] Frontend
echo "[3/4] Setting up frontend..."
cd frontend
npm install --silent
cd ..

echo "[4/4] Setup complete."
echo
echo "================================"
echo "Start MAILOX (one terminal each):"
echo "================================"
echo
echo "API:"
echo "  cd backend && . venv/bin/activate && uvicorn app.main:app --host 127.0.0.1 --port 8000"
echo
echo "Worker:"
echo "  cd backend && . venv/bin/activate && celery -A app.worker.celery_app worker --loglevel=info"
echo
echo "Scheduler (scheduled scans, monitoring, stalled-scan recovery):"
echo "  cd backend && . venv/bin/activate && celery -A app.worker.celery_app beat --loglevel=info"
echo
echo "Frontend:"
echo "  cd frontend && npm run dev"
echo
echo "Then open http://localhost:5173"
echo
