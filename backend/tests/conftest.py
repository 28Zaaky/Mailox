"""
Test fixtures for MAILOX backend.
Requires PostgreSQL with a `mailox_test` database. Credentials come from
TEST_DATABASE_URL / TEST_DATABASE_URL_SYNC when set, otherwise from the
DATABASE_URL in backend/.env with the database name swapped for `mailox_test`.
Set TEST_DB_SCHEMA to run a suite in its own schema (parallel runs on one DB).

Design:
  - Tables created ONCE synchronously (session scope, no event loop issues)
  - Each test gets a function-scoped async engine with NullPool (no cross-loop problems)
  - Each test runs inside an outer transaction (endpoint commits become
    SAVEPOINTs) that is rolled back at the end (clean isolation)
"""
import os
import re
from pathlib import Path
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine



def _resolve_test_db_urls() -> tuple[str, str]:
    """Test DB URLs from TEST_DATABASE_URL(_SYNC), else backend/.env pointed at mailox_test."""
    async_url = os.environ.get("TEST_DATABASE_URL")
    sync_url = os.environ.get("TEST_DATABASE_URL_SYNC")
    if async_url and sync_url:
        return async_url, sync_url
    env_file = Path(__file__).resolve().parent.parent / ".env"
    base = None
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("DATABASE_URL="):
                base = line.split("=", 1)[1].strip()
                break
    if not base:
        base = "postgresql+asyncpg://mailox:mailox_pass@127.0.0.1:5432/mailox"
    if not async_url:
        head, _, query = base.partition("?")
        async_url = head.rsplit("/", 1)[0] + "/mailox_test" + (f"?{query}" if query else "")
    sync_url = sync_url or async_url.replace("+asyncpg", "+psycopg2", 1)
    return async_url, sync_url


TEST_DB_URL_ASYNC, TEST_DB_URL_SYNC = _resolve_test_db_urls()
TEST_DB_SCHEMA = os.environ.get("TEST_DB_SCHEMA", "").strip()
if TEST_DB_SCHEMA and not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", TEST_DB_SCHEMA):
    raise RuntimeError("TEST_DB_SCHEMA must be a lowercase SQL identifier")

# Configure env BEFORE any app module is imported
os.environ.setdefault("TESTING", "true")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", TEST_DB_URL_ASYNC)
os.environ.setdefault("DATABASE_URL_SYNC", TEST_DB_URL_SYNC)
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6379/1")
os.environ.setdefault("SECRET_KEY", "test_secret_key_for_tests_only_min_32_chars_long")
os.environ.setdefault("REFRESH_SECRET_KEY", "test_refresh_key_for_tests_only_min_32_chars__")
os.environ.setdefault("MASTER_ENCRYPTION_KEY", "test_master_key_for_tests_only_min_32_chars__!")
os.environ.setdefault("ALLOWED_ORIGINS", "http://localhost:5173")
os.environ.setdefault("CELERY_BROKER_URL", "redis://127.0.0.1:6379/1")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://127.0.0.1:6379/2")
os.environ.setdefault("RATE_LIMIT_AUTH_RPM", "1000")

if TEST_DB_SCHEMA:
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    # search_path goes in the connection startup parameters (every engine, sync and
    # async), so it survives the RESET ALL / DISCARD issued when connections are recycled.
    @event.listens_for(Engine, "do_connect")
    def _set_search_path(dialect, _conn_rec, _cargs, cparams):
        if dialect.driver == "asyncpg":
            cparams.setdefault("server_settings", {})["search_path"] = TEST_DB_SCHEMA
        else:
            cparams["options"] = f"-c search_path={TEST_DB_SCHEMA}"

from app.core.config import settings  # noqa: E402
from app.db.models import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402

# Session of the running test, used by helpers that must write directly to the DB
_CURRENT_DB: "AsyncSession | None" = None


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create all tables synchronously once per session, drop at end.

    The schema is dropped with CASCADE rather than metadata.drop_all(): the
    monitoring_schedules <-> scans FK cycle makes drop_all fail, which left
    tables behind and broke the next run.
    """
    from sqlalchemy import text

    schema = TEST_DB_SCHEMA or "public"
    engine = create_engine(TEST_DB_URL_SYNC, echo=False)

    def _reset_schema() -> None:
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
            conn.execute(text(f"CREATE SCHEMA {schema}"))

    _reset_schema()
    Base.metadata.create_all(engine)
    yield
    _reset_schema()
    engine.dispose()


@pytest_asyncio.fixture
async def db() -> AsyncGenerator[AsyncSession, None]:
    """
    Function-scoped async session with NullPool (no connection pooling →
    no cross-event-loop issues). Rolls back after each test.
    """
    global _CURRENT_DB
    engine = create_async_engine(TEST_DB_URL_ASYNC, poolclass=NullPool, echo=False)
    # Outer transaction + SAVEPOINT per session.commit(): endpoints can commit
    # and roll back exactly like in production (get_db), while everything is
    # still discarded at the end of the test.
    async with engine.connect() as conn:
        outer = await conn.begin()
        session = AsyncSession(
            bind=conn,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )
        _CURRENT_DB = session
        # Code under test that opens its own sessions (worker tasks, SSE,
        # email log) must see this test's data: bind AsyncSessionLocal to the
        # same connection/outer transaction for the duration of the test.
        import app.db.session as _db_session
        import app.services.email_service as _email_service
        import app.worker.webhook_dispatch as _webhook_dispatch
        bound_factory = async_sessionmaker(
            bind=conn, expire_on_commit=False, join_transaction_mode="create_savepoint",
        )
        patched = [(m, m.AsyncSessionLocal) for m in (_db_session, _email_service, _webhook_dispatch)]
        for mod, _ in patched:
            mod.AsyncSessionLocal = bound_factory
        try:
            yield session
        finally:
            for mod, original in patched:
                mod.AsyncSessionLocal = original
            _CURRENT_DB = None
            await session.close()
            if outer.is_active:
                await outer.rollback()
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Test HTTP client wired to the per-test DB session."""
    async def _override_get_db():
        # Same commit/rollback semantics as app.db.session.get_db, so tests see
        # what production does when an endpoint raises after a write.
        try:
            yield db
            await db.commit()
        except Exception:
            await db.rollback()
            raise

    app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://test"
    ) as ac:
        yield ac
    app.dependency_overrides.clear()


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "edition(name): run the test with MAILOX_EDITION=name ('saas' when absent)",
    )


@pytest.fixture(autouse=True)
def pin_edition(request, monkeypatch):
    """Pin MAILOX_EDITION per test instead of inheriting it from the environment.

    The suite must give the same result whatever MAILOX_EDITION the shell exports.
    Tests run as SaaS (the Settings default most of them were written against)
    unless marked @pytest.mark.edition("selfhosted"); a test or class fixture may
    still monkeypatch it afterwards.
    """
    marker = request.node.get_closest_marker("edition")
    edition = marker.args[0] if marker else "saas"
    assert edition in ("saas", "selfhosted"), edition
    monkeypatch.setattr(settings, "MAILOX_EDITION", edition)
    return edition


@pytest.fixture(autouse=True)
def fast_sse(monkeypatch):
    """Speed up SSE polling for all tests: 0.1s intervals, max 5 events.

    Without this, the SSE generator sleeps 2s between polls and runs up to 500
    events. In tests, the generator must terminate naturally (exhaust SSE_MAX_EVENTS)
    so Starlette sends more_body=False, allowing httpx ASGITransport to close cleanly.
    Set reauth and heartbeat intervals very high so they don't fire during 5-event tests.
    """
    monkeypatch.setattr(settings, "SSE_POLL_INTERVAL", 0.1)
    monkeypatch.setattr(settings, "SSE_MAX_EVENTS", 5)
    monkeypatch.setattr(settings, "SSE_REAUTH_INTERVAL_SECONDS", 9999.0)
    monkeypatch.setattr(settings, "SSE_HEARTBEAT_INTERVAL_SECONDS", 9999.0)


@pytest.fixture(autouse=True)
def stub_rate_limiter(request, monkeypatch):
    """
    Replace the distributed Redis rate limiter with a no-op for all unit tests.
    Tests marked with @pytest.mark.real_distributed skip this stub.
    """
    if request.node.get_closest_marker("real_distributed"):
        return

    import app.api.deps as _deps

    async def _noop_rate_limit() -> None:
        return

    # Routes captured the function objects at import time (Depends(...)), so
    # patching the module attribute has no effect: override the dependencies.
    for dep in (_deps.rate_limit_auth, _deps.rate_limit_refresh):
        app.dependency_overrides[dep] = _noop_rate_limit
        request.addfinalizer(lambda d=dep: app.dependency_overrides.pop(d, None))


@pytest.fixture(autouse=True)
def stub_sse_manager(request, monkeypatch):
    """
    Replace distributed Redis SSE lease manager with in-memory stubs for unit tests.
    Tests marked with @pytest.mark.real_distributed skip this stub.
    """
    if request.node.get_closest_marker("real_distributed"):
        return

    import app.core.sse_manager as _mgr

    async def _acquire(org_id: str):
        import uuid as _u
        conn_id = _u.uuid4().hex
        return conn_id, "ok"

    async def _release(org_id: str, conn_id: str) -> None:
        return

    async def _heartbeat(org_id: str, conn_id: str) -> bool:
        return True

    monkeypatch.setattr(_mgr, "acquire_sse_slot", _acquire)
    monkeypatch.setattr(_mgr, "release_sse_slot", _release)
    monkeypatch.setattr(_mgr, "heartbeat_sse_slot", _heartbeat)


# ── Helpers ──────────────────────────────────────────────────────────────────

TEST_EMAIL = "test@example.com"
TEST_PASSWORD = "TestPass1!SecureEnough"


async def make_invite(email: str) -> str:
    """Issue a signup invite for `email` in the current test session; returns the raw token."""
    from app.services.access_service import AccessService

    assert _CURRENT_DB is not None, "make_invite needs the db/client fixtures"
    invite = await AccessService(_CURRENT_DB).issue_invite(email, "", None, send=False)
    return invite.plain_token  # type: ignore[attr-defined]


async def verify_domain(org_id, domain: str = "example.com") -> None:
    """Mark `domain` as verified for `org_id` in the current test session.

    In the SaaS edition (the default) a scan is only accepted for a domain the
    org has proven it controls (DNS TXT). Tests that are not about that proof
    record it directly instead of going through a real DNS lookup.
    """
    import uuid as _uuid
    from datetime import datetime, timezone

    from app.db.models.access import VerifiedDomain

    assert _CURRENT_DB is not None, "verify_domain needs the db/client fixtures"
    if isinstance(org_id, str):
        org_id = _uuid.UUID(org_id)
    now = datetime.now(timezone.utc)
    _CURRENT_DB.add(VerifiedDomain(
        org_id=org_id, domain=domain, token="test-token",
        verified_at=now, last_checked_at=now,
    ))
    # Commit (a SAVEPOINT release here, the outer transaction is still rolled back
    # at teardown) so a later request that fails and rolls back keeps the proof.
    await _CURRENT_DB.commit()


async def ensure_instance_owner() -> None:
    """Self-hosted: make sure the instance already has its first account.

    On an empty self-hosted instance the first registration becomes platform
    admin. Test users created through register_user() must be ordinary accounts
    (as on SaaS, where the admin comes from the CLI), otherwise tenant-isolation
    checks would pass or fail for the wrong reason.
    """
    import uuid as _uuid
    from sqlalchemy import func, select

    from app.core.security import hash_password
    from app.db.models.user import User

    assert _CURRENT_DB is not None, "ensure_instance_owner needs the db/client fixtures"
    if settings.IS_SAAS:
        return
    if (await _CURRENT_DB.execute(select(func.count()).select_from(User))).scalar_one():
        return
    _CURRENT_DB.add(User(
        email=f"owner-{_uuid.uuid4().hex[:10]}@instance-owner.dev",
        password_hash=hash_password(_uuid.uuid4().hex),
        is_platform_admin=True,
    ))
    await _CURRENT_DB.commit()


async def register_user(
    client: AsyncClient,
    email: str = TEST_EMAIL,
    password: str = TEST_PASSWORD,
) -> dict:
    # Registration is invite-only (and SaaS never grants first-user admin):
    # issue an invite in the test session, then go through the real endpoint.
    await ensure_instance_owner()
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "invite": await make_invite(email)},
    )
    assert resp.status_code == 201, f"register failed [{resp.status_code}]: {resp.text}"
    return resp.json()


async def login_user(
    client: AsyncClient,
    email: str = TEST_EMAIL,
    password: str = TEST_PASSWORD,
) -> dict:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"login failed [{resp.status_code}]: {resp.text}"
    return {
        "access_token": resp.json()["access_token"],
        "refresh_token": resp.cookies.get("refresh_token"),
    }


def auth_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}
