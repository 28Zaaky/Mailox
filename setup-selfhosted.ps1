# MAILOX self-hosted setup, manual path (Windows).
# Run from the repository root: .\setup-selfhosted.ps1
# Requires Python 3.12+, Node.js 20+, a running PostgreSQL with the mailox role and
# database (see README.md), and Redis for the worker.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# 32 random bytes, lowercase hex (same format as secrets.token_hex(32)).
# Instance API so it also runs on Windows PowerShell 5.1 (.NET Framework has no ToHexString).
function New-HexKey {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

# Copies .env.selfhosted to .env in $Dir and replaces the three CHANGEME keys.
function Initialize-BackendEnv {
    param([Parameter(Mandatory)][string]$Dir)
    $template = Join-Path $Dir ".env.selfhosted"
    $target = Join-Path $Dir ".env"
    $envText = [IO.File]::ReadAllText($template)
    $envText = $envText.Replace('CHANGEME_generate_with_command_above_1111111111111111', (New-HexKey))
    $envText = $envText.Replace('CHANGEME_generate_with_command_above_2222222222222222', (New-HexKey))
    $envText = $envText.Replace('CHANGEME_generate_with_command_above_3333333333333333', (New-HexKey))
    if ($envText -match 'CHANGEME_') {
        throw "Key generation failed: placeholders remain, $target not written."
    }
    [IO.File]::WriteAllText($target, $envText, (New-Object Text.UTF8Encoding $false))
}

Write-Host "================================" -ForegroundColor Cyan
Write-Host "MAILOX self-hosted setup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host

# Requirements
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python 3.12+ is required but was not found." -ForegroundColor Red
    exit 1
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "npm (Node.js 20+) is required but was not found." -ForegroundColor Red
    exit 1
}
$redisUp = $false
try {
    $tcp = New-Object Net.Sockets.TcpClient
    $redisUp = $tcp.ConnectAsync("127.0.0.1", 6379).Wait(1000)
    $tcp.Dispose()
} catch { $redisUp = $false }
if (-not $redisUp) {
    Write-Host "Warning: Redis does not answer on localhost:6379. Start it before you start the worker." -ForegroundColor Yellow
}

# [1/4] Backend
Write-Host "[1/4] Setting up backend..." -ForegroundColor Yellow
Set-Location backend

if (-not (Test-Path "venv")) {
    python -m venv venv
}
& .\venv\Scripts\Activate.ps1
python -m pip install -q -r requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Host "pip install failed, setup aborted." -ForegroundColor Red; exit 1 }

if (-not (Test-Path ".env")) {
    Initialize-BackendEnv -Dir (Get-Location).Path
    Write-Host "   Generated secure keys in backend\.env" -ForegroundColor Green
} else {
    Write-Host "   backend\.env already exists, skipping" -ForegroundColor Gray
}

# [2/4] Database migrations
Write-Host "[2/4] Running database migrations..." -ForegroundColor Yellow
python -m alembic upgrade head
if ($LASTEXITCODE -ne 0) {
    Write-Host "Database migrations failed, setup aborted." -ForegroundColor Red
    Write-Host "   Create the role and database first (as a PostgreSQL superuser):" -ForegroundColor Yellow
    Write-Host "     psql -U postgres -c `"CREATE ROLE mailox LOGIN PASSWORD 'mailox';`""
    Write-Host "     psql -U postgres -c `"CREATE DATABASE mailox OWNER mailox;`""
    Write-Host "   then run this script again." -ForegroundColor Yellow
    exit 1
}

Set-Location ..

# [3/4] Frontend
Write-Host "[3/4] Setting up frontend..." -ForegroundColor Yellow
Set-Location frontend
npm install --silent
if ($LASTEXITCODE -ne 0) { Write-Host "npm install failed, setup aborted." -ForegroundColor Red; exit 1 }
Set-Location ..

Write-Host "[4/4] Setup complete." -ForegroundColor Green
Write-Host
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Start MAILOX (one terminal each):" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host
Write-Host "API:" -ForegroundColor Yellow
Write-Host "  cd backend; .\venv\Scripts\Activate.ps1; uvicorn app.main:app --host 127.0.0.1 --port 8000"
Write-Host
Write-Host "Worker (--pool=solo: the default prefork pool does not work on Windows):" -ForegroundColor Yellow
Write-Host "  cd backend; .\venv\Scripts\Activate.ps1; celery -A app.worker.celery_app worker --loglevel=info --pool=solo"
Write-Host
Write-Host "Scheduler (scheduled scans, monitoring, stalled-scan recovery):" -ForegroundColor Yellow
Write-Host "  cd backend; .\venv\Scripts\Activate.ps1; celery -A app.worker.celery_app beat --loglevel=info"
Write-Host
Write-Host "Frontend:" -ForegroundColor Yellow
Write-Host "  cd frontend; npm run dev"
Write-Host
Write-Host "Then open http://localhost:5173" -ForegroundColor Green
Write-Host
