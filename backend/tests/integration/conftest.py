"""
Integration test fixtures requiring the full Docker stack.

Skip all tests unless MAILOX_INTEGRATION_TESTS=1 is set.
Expects:
  PostgreSQL: postgresql://mailox:mailox_pass@127.0.0.1:5433/mailox_test
  Redis:      redis://:redis_test_pass@127.0.0.1:6380/0
  API:        http://127.0.0.1:8001
  2 Celery workers + Beat (started via docker compose -f docker-compose.test.yml up)

Run:
  docker compose -f docker-compose.test.yml up -d
  MAILOX_INTEGRATION_TESTS=1 pytest tests/integration/ -v
"""
import os
import uuid
from typing import AsyncGenerator

import pytest
import pytest_asyncio

INTEGRATION = os.getenv("MAILOX_INTEGRATION_TESTS", "").strip() == "1"
SKIP_REASON = "Set MAILOX_INTEGRATION_TESTS=1 and start docker compose -f docker-compose.test.yml up"

INT_DB_URL = "postgresql+asyncpg://mailox:mailox_pass@127.0.0.1:5433/mailox_test"
INT_DB_URL_SYNC = "postgresql+psycopg2://mailox:mailox_pass@127.0.0.1:5433/mailox_test"
INT_API_URL = "http://127.0.0.1:8001"

pytestmark = pytest.mark.skipif(not INTEGRATION, reason=SKIP_REASON)


@pytest_asyncio.fixture(scope="module")
async def int_db():
    """Async DB session against the Docker PostgreSQL."""
    from sqlalchemy.pool import NullPool
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    engine = create_async_engine(INT_DB_URL, poolclass=NullPool)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as session:
        yield session
        await session.rollback()
    await engine.dispose()


@pytest_asyncio.fixture(scope="module")
async def int_client():
    """HTTP client against the Docker API."""
    import httpx
    async with httpx.AsyncClient(base_url=INT_API_URL, timeout=30.0) as client:
        yield client


@pytest_asyncio.fixture
async def int_user(int_client):
    """Register + login a fresh user. Returns (token, user_id)."""
    email = f"int-{uuid.uuid4()}@test.dev"
    pw = "IntPass1!SecureEnough"
    r = await int_client.post("/api/v1/auth/register", json={"email": email, "password": pw})
    assert r.status_code == 201, r.text
    r = await int_client.post("/api/v1/auth/login", json={"email": email, "password": pw})
    token = r.json()["access_token"]
    return token, r.json().get("user_id", "")


@pytest_asyncio.fixture
async def int_org(int_client, int_user):
    """Create org for the test user. Returns (token, org_id)."""
    token, _ = int_user
    hdrs = {"Authorization": f"Bearer {token}"}
    r = await int_client.post(
        "/api/v1/orgs",
        json={"name": f"int-org-{uuid.uuid4()}", "slug": f"int-{uuid.uuid4()}"},
        headers=hdrs,
    )
    assert r.status_code == 201, r.text
    return token, r.json()["id"]
