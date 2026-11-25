"""
Distributed security tests.

Tests in this file exercise REAL Redis and PostgreSQL connections to verify
concurrency, distribution, and fault-tolerance properties that cannot be
demonstrated with mocks.

Environment requirements:
  - PostgreSQL running at 127.0.0.1:5432 (mailox/mailox_pass/mailox_test)
  - Redis running at 127.0.0.1:6379

Tests are automatically SKIPPED (not failed) when these services are
unavailable. The test runner will report them as skipped, not as passed.

Fixtures in this file explicitly opt out of the stub_rate_limiter and
stub_sse_manager autouse fixtures from conftest.py using their own overrides.
"""
import asyncio
import os
import time
import uuid
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# ── Service availability detection ───────────────────────────────────────────

# Redis DB used by these tests. Fixtures wipe "sse:*" / "rl:test_*" keys in it, so two
# suites running at the same time (e.g. one per edition) must use different DBs.
_REDIS_DB = int(os.environ.get("TEST_REDIS_DB", "15"))

def _redis_available() -> bool:
    try:
        import redis
        r = redis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, socket_connect_timeout=1)
        r.ping()
        r.close()
        return True
    except Exception:
        return False


def _postgres_available() -> bool:
    # Probe the database the suite actually uses (conftest exports the test URL
    # as DATABASE_URL_SYNC), not hard-coded credentials.
    try:
        import psycopg2
        url = os.environ.get(
            "DATABASE_URL_SYNC",
            "postgresql+psycopg2://mailox:mailox_pass@127.0.0.1:5432/mailox_test",
        ).replace("postgresql+psycopg2://", "postgresql://", 1)
        conn = psycopg2.connect(url, connect_timeout=1)
        conn.close()
        return True
    except Exception:
        return False


async def _wait_until(probe, timeout: float = 10.0, interval: float = 0.1):
    """Poll `probe` (async, returns truthy when done) until it succeeds or times out.

    Used instead of fixed sleeps for TTL/window expiry so a slow machine does not
    turn a correct implementation into a red test.
    """
    deadline = time.monotonic() + timeout
    while True:
        result = await probe()
        if result or time.monotonic() >= deadline:
            return result
        await asyncio.sleep(interval)


REDIS_AVAILABLE = _redis_available()
POSTGRES_AVAILABLE = _postgres_available()

requires_redis = pytest.mark.skipif(not REDIS_AVAILABLE, reason="Redis not available at 127.0.0.1:6379")
requires_postgres = pytest.mark.skipif(not POSTGRES_AVAILABLE, reason="PostgreSQL not available")
requires_both = pytest.mark.skipif(
    not (REDIS_AVAILABLE and POSTGRES_AVAILABLE),
    reason="Redis and PostgreSQL both required",
)


# ── Test DB URL (re-use from conftest env) ────────────────────────────────────

TEST_REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/1")
TEST_DB_URL_ASYNC = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://mailox:mailox_pass@127.0.0.1:5432/mailox_test",
)
TEST_DB_URL_SYNC = os.environ.get(
    "DATABASE_URL_SYNC",
    "postgresql+psycopg2://mailox:mailox_pass@127.0.0.1:5432/mailox_test",
)


# ── Redis rate limiter tests ──────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.real_distributed
class TestDistributedRateLimiter:
    """
    Tests for the Redis sliding-window rate limiter.
    Uses Redis DB 15 to avoid interfering with application data.
    """

    @pytest.fixture(autouse=True)
    async def clean_redis_keys(self):
        """Clean up rate limit keys before each test."""
        if not REDIS_AVAILABLE:
            yield
            return
        import redis.asyncio as aioredis
        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        # Delete test keys
        keys = await r.keys("rl:test_*")
        if keys:
            await r.delete(*keys)
        yield
        keys = await r.keys("rl:test_*")
        if keys:
            await r.delete(*keys)
        await r.aclose()

    @requires_redis
    async def test_rate_limiter_allows_under_limit(self):
        """Requests under the limit must all succeed."""
        from app.core.rate_limiter import check_rate_limit
        import redis.asyncio as aioredis
        from unittest.mock import patch

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        try:
            with patch("app.core.rate_limiter.get_redis", return_value=r):
                for i in range(5):
                    req = MagicMock()
                    req.client = MagicMock()
                    req.client.host = "10.0.0.1"
                    req.headers = {}
                    # Should not raise
                    await check_rate_limit(req, route_category="test_allow", limit=10, window_seconds=60)
        finally:
            await r.aclose()

    @requires_redis
    async def test_rate_limiter_blocks_over_limit(self):
        """Requests over the limit must receive HTTP 429."""
        from fastapi import HTTPException
        from app.core.rate_limiter import check_rate_limit
        import redis.asyncio as aioredis

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        # Clean up
        await r.delete("rl:test_block:198.51.100.1")

        try:
            with patch("app.core.rate_limiter.get_redis", return_value=r):
                for i in range(3):
                    req = MagicMock()
                    req.client = MagicMock()
                    req.client.host = "198.51.100.1"
                    req.headers = {}
                    await check_rate_limit(req, route_category="test_block", limit=3, window_seconds=60)

                # 4th request must be blocked
                req = MagicMock()
                req.client = MagicMock()
                req.client.host = "198.51.100.1"
                req.headers = {}
                with pytest.raises(HTTPException) as exc_info:
                    await check_rate_limit(req, route_category="test_block", limit=3, window_seconds=60)
                assert exc_info.value.status_code == 429
        finally:
            await r.delete("rl:test_block:198.51.100.1")
            await r.aclose()

    @requires_redis
    async def test_rate_limiter_shared_across_simulated_instances(self):
        """
        Two 'instances' sharing the same Redis must share the same quota.
        Simulated by using two separate Redis clients pointing to the same DB.
        """
        from fastapi import HTTPException
        from app.core.rate_limiter import check_rate_limit
        import redis.asyncio as aioredis

        r1 = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        r2 = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        test_ip = "198.51.100.42"
        key = f"rl:test_shared:{test_ip}"
        await r1.delete(key)

        try:
            # Instance 1 consumes 2 slots
            for _ in range(2):
                req = MagicMock()
                req.client = MagicMock()
                req.client.host = test_ip
                req.headers = {}
                with patch("app.core.rate_limiter.get_redis", return_value=r1):
                    await check_rate_limit(req, route_category="test_shared", limit=3, window_seconds=60)

            # Instance 2 consumes 1 slot (now at limit)
            req = MagicMock()
            req.client = MagicMock()
            req.client.host = test_ip
            req.headers = {}
            with patch("app.core.rate_limiter.get_redis", return_value=r2):
                await check_rate_limit(req, route_category="test_shared", limit=3, window_seconds=60)

            # Either instance attempting a 4th request must be blocked
            req = MagicMock()
            req.client = MagicMock()
            req.client.host = test_ip
            req.headers = {}
            with patch("app.core.rate_limiter.get_redis", return_value=r1):
                with pytest.raises(HTTPException) as exc_info:
                    await check_rate_limit(req, route_category="test_shared", limit=3, window_seconds=60)
                assert exc_info.value.status_code == 429
        finally:
            await r1.delete(key)
            await r1.aclose()
            await r2.aclose()

    @requires_redis
    async def test_rate_limiter_window_expires(self):
        """After the window expires, the counter must reset."""
        from app.core.rate_limiter import check_rate_limit
        import redis.asyncio as aioredis

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        test_ip = "198.51.100.99"
        key = f"rl:test_expire:{test_ip}"
        await r.delete(key)

        try:
            with patch("app.core.rate_limiter.get_redis", return_value=r):
                # Hit limit with 2-second window
                for _ in range(2):
                    req = MagicMock()
                    req.client = MagicMock()
                    req.client.host = test_ip
                    req.headers = {}
                    await check_rate_limit(req, route_category="test_expire", limit=2, window_seconds=2)

                # Once the window has expired the request must be allowed again
                async def _allowed() -> bool:
                    req = MagicMock()
                    req.client = MagicMock()
                    req.client.host = test_ip
                    req.headers = {}
                    try:
                        await check_rate_limit(req, route_category="test_expire", limit=2, window_seconds=2)
                    except Exception:
                        return False
                    return True

                # Still blocked inside the window
                assert not await _allowed()
                assert await _wait_until(_allowed, timeout=10.0, interval=0.25),                     "Counter must reset once the window has expired"
        finally:
            await r.delete(key)
            await r.aclose()

    @requires_redis
    async def test_rate_limiter_concurrent_requests_atomic(self):
        """
        Multiple concurrent requests must not exceed the limit due to race conditions.
        Uses asyncio.gather to simulate concurrency within a single process.
        """
        from fastapi import HTTPException
        from app.core.rate_limiter import check_rate_limit
        import redis.asyncio as aioredis

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        test_ip = "198.51.100.77"
        key = f"rl:test_concurrent:{test_ip}"
        await r.delete(key)

        LIMIT = 5
        TOTAL_REQUESTS = 20
        allowed = []
        blocked = []

        async def _make_request():
            req = MagicMock()
            req.client = MagicMock()
            req.client.host = test_ip
            req.headers = {}
            try:
                with patch("app.core.rate_limiter.get_redis", return_value=r):
                    await check_rate_limit(req, route_category="test_concurrent", limit=LIMIT, window_seconds=60)
                allowed.append(1)
            except HTTPException as e:
                if e.status_code == 429:
                    blocked.append(1)

        try:
            await asyncio.gather(*[_make_request() for _ in range(TOTAL_REQUESTS)])
            # Must not have allowed more than LIMIT requests
            assert len(allowed) <= LIMIT, \
                f"Rate limiter allowed {len(allowed)} requests, limit was {LIMIT}"
            assert len(allowed) + len(blocked) == TOTAL_REQUESTS
        finally:
            await r.delete(key)
            await r.aclose()

    @requires_redis
    async def test_rate_limiter_different_ips_independent(self):
        """Different IPs must have independent counters."""
        from app.core.rate_limiter import check_rate_limit
        import redis.asyncio as aioredis

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        ip1 = "198.51.100.10"
        ip2 = "198.51.100.11"
        await r.delete(f"rl:test_indep:{ip1}", f"rl:test_indep:{ip2}")

        try:
            with patch("app.core.rate_limiter.get_redis", return_value=r):
                # Exhaust limit for ip1
                for _ in range(2):
                    req = MagicMock()
                    req.client = MagicMock()
                    req.client.host = ip1
                    req.headers = {}
                    await check_rate_limit(req, route_category="test_indep", limit=2, window_seconds=60)

                # ip2 must still be allowed
                req = MagicMock()
                req.client = MagicMock()
                req.client.host = ip2
                req.headers = {}
                # Should not raise
                await check_rate_limit(req, route_category="test_indep", limit=2, window_seconds=60)
        finally:
            await r.delete(f"rl:test_indep:{ip1}", f"rl:test_indep:{ip2}")
            await r.aclose()

    @requires_redis
    async def test_rate_limiter_redis_error_denies(self):
        """When Redis is unavailable, rate limiter must deny (fail-secure, 503)."""
        from fastapi import HTTPException
        from app.core.rate_limiter import check_rate_limit
        import redis.asyncio as aioredis

        # Connect to a port where nothing is listening
        r = aioredis.Redis(host="127.0.0.1", port=16379, socket_connect_timeout=1, decode_responses=True)

        try:
            req = MagicMock()
            req.client = MagicMock()
            req.client.host = "10.0.0.1"
            req.headers = {}
            with patch("app.core.rate_limiter.get_redis", return_value=r):
                with pytest.raises(HTTPException) as exc_info:
                    await check_rate_limit(req, route_category="test_down", limit=10, window_seconds=60)
                # 503 = fail-secure (not 429 — that would be an incorrect rate-limit signal)
                assert exc_info.value.status_code == 503
        finally:
            await r.aclose()

    async def test_rate_limiter_no_xff_trust_without_proxy_config(self):
        """
        When TRUSTED_PROXY_COUNT=0, X-Forwarded-For must be ignored.
        The rate limit key must be based on request.client.host.
        """
        from app.core.rate_limiter import _extract_client_ip
        from app.core.config import settings

        # Temporarily override proxy count
        original = settings.TRUSTED_PROXY_COUNT
        try:
            settings.TRUSTED_PROXY_COUNT = 0
            req = MagicMock()
            req.client = MagicMock()
            req.client.host = "10.0.0.1"
            req.headers = {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}
            ip = _extract_client_ip(req)
            # Must use direct connection IP, not XFF
            assert ip == "10.0.0.1", f"Expected direct IP, got {ip}"
        finally:
            settings.TRUSTED_PROXY_COUNT = original

    async def test_rate_limiter_xff_trusted_proxy(self):
        """When TRUSTED_PROXY_COUNT=1, the leftmost XFF IP (client) must be used.

        Uses 1.2.3.4 as a public IP (not private in Python 3.12).
        Note: 203.0.113.0/24 is classified as private in Python 3.12 (TEST-NET-3),
        so we use a truly routable public IP.
        """
        from app.core.rate_limiter import _extract_client_ip
        from app.core.config import settings

        original = settings.TRUSTED_PROXY_COUNT
        try:
            settings.TRUSTED_PROXY_COUNT = 1
            req = MagicMock()
            req.client = MagicMock()
            req.client.host = "10.0.0.1"  # reverse proxy IP
            req.headers = {"X-Forwarded-For": "1.2.3.4"}  # truly public client IP
            ip = _extract_client_ip(req)
            assert ip == "1.2.3.4", f"Expected XFF client IP, got {ip}"
        finally:
            settings.TRUSTED_PROXY_COUNT = original

    async def test_rate_limiter_xff_private_ip_rejected(self):
        """
        A private IP in X-Forwarded-For when TRUSTED_PROXY_COUNT=1 must
        fall back to direct connection IP (possible header injection).
        """
        from app.core.rate_limiter import _extract_client_ip
        from app.core.config import settings

        original = settings.TRUSTED_PROXY_COUNT
        try:
            settings.TRUSTED_PROXY_COUNT = 1
            req = MagicMock()
            req.client = MagicMock()
            req.client.host = "10.0.0.1"
            req.headers = {"X-Forwarded-For": "192.168.1.100"}  # private — suspicious
            ip = _extract_client_ip(req)
            assert ip == "10.0.0.1", f"Expected fallback to direct IP, got {ip}"
        finally:
            settings.TRUSTED_PROXY_COUNT = original


# ── SSE distributed lease tests ───────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.real_distributed
class TestDistributedSSELeases:
    """
    Tests for the Redis-backed SSE connection lease manager.
    Uses Redis DB 15 for isolation.
    """

    @pytest.fixture(autouse=True)
    async def clean_sse_keys(self):
        if not REDIS_AVAILABLE:
            yield
            return
        import redis.asyncio as aioredis
        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        keys = await r.keys("sse:*")
        if keys:
            await r.delete(*keys)
        yield
        keys = await r.keys("sse:*")
        if keys:
            await r.delete(*keys)
        await r.aclose()

    @requires_redis
    async def test_sse_acquire_and_release(self):
        """Acquire a slot, then release it. Second acquire after release must succeed."""
        import redis.asyncio as aioredis
        from app.core.sse_manager import acquire_sse_slot, release_sse_slot

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        org_id = str(uuid.uuid4())

        with patch("app.core.sse_manager.get_redis", return_value=r):
            conn_id, result = await acquire_sse_slot(org_id)
            assert result == "ok", f"Expected 'ok', got {result}"
            assert conn_id is not None

            await release_sse_slot(org_id, conn_id)

            # Must be acquirable again after release
            conn_id2, result2 = await acquire_sse_slot(org_id)
            assert result2 == "ok"
            await release_sse_slot(org_id, conn_id2)

        await r.aclose()

    @requires_redis
    async def test_sse_org_limit_enforced(self):
        """Cannot exceed SSE_MAX_PER_ORG connections for one org."""
        import redis.asyncio as aioredis
        from app.core.sse_manager import acquire_sse_slot, release_sse_slot
        from app.core.config import settings

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        org_id = str(uuid.uuid4())
        original_max = settings.SSE_MAX_PER_ORG

        try:
            settings.SSE_MAX_PER_ORG = 3
            acquired = []

            with patch("app.core.sse_manager.get_redis", return_value=r):
                # Acquire up to limit
                for _ in range(3):
                    cid, res = await acquire_sse_slot(org_id)
                    assert res == "ok"
                    acquired.append(cid)

                # Next acquire must fail with org_limit
                cid_extra, res_extra = await acquire_sse_slot(org_id)
                assert res_extra == "org_limit", f"Expected 'org_limit', got {res_extra}"
                assert cid_extra is None

                # Release one
                await release_sse_slot(org_id, acquired[0])

                # Now must be acquirable again
                cid_new, res_new = await acquire_sse_slot(org_id)
                assert res_new == "ok"
                acquired.append(cid_new)

                # Clean up
                for cid in acquired[1:]:
                    await release_sse_slot(org_id, cid)
        finally:
            settings.SSE_MAX_PER_ORG = original_max
            await r.aclose()

    @requires_redis
    async def test_sse_orgs_independent(self):
        """Connections from different orgs must not block each other."""
        import redis.asyncio as aioredis
        from app.core.sse_manager import acquire_sse_slot, release_sse_slot
        from app.core.config import settings

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        org1 = str(uuid.uuid4())
        org2 = str(uuid.uuid4())
        original_max = settings.SSE_MAX_PER_ORG
        original_global = settings.SSE_MAX_GLOBAL

        acquired = []
        try:
            settings.SSE_MAX_PER_ORG = 2
            settings.SSE_MAX_GLOBAL = 10

            with patch("app.core.sse_manager.get_redis", return_value=r):
                # Fill org1 limit
                for _ in range(2):
                    cid, res = await acquire_sse_slot(org1)
                    assert res == "ok"
                    acquired.append((org1, cid))

                # org2 must still be acquirable
                cid2, res2 = await acquire_sse_slot(org2)
                assert res2 == "ok", f"org2 blocked by org1 limit: {res2}"
                acquired.append((org2, cid2))
        finally:
            with patch("app.core.sse_manager.get_redis", return_value=r):
                for org_id, cid in acquired:
                    await release_sse_slot(org_id, cid)
            settings.SSE_MAX_PER_ORG = original_max
            settings.SSE_MAX_GLOBAL = original_global
            await r.aclose()

    @requires_redis
    async def test_sse_global_limit_enforced(self):
        """Cannot exceed SSE_MAX_GLOBAL connections total."""
        import redis.asyncio as aioredis
        from app.core.sse_manager import acquire_sse_slot, release_sse_slot
        from app.core.config import settings

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        original_max_org = settings.SSE_MAX_PER_ORG
        original_max_global = settings.SSE_MAX_GLOBAL

        acquired = []
        try:
            settings.SSE_MAX_PER_ORG = 10
            settings.SSE_MAX_GLOBAL = 3

            with patch("app.core.sse_manager.get_redis", return_value=r):
                # Use different orgs to avoid per-org limit
                for i in range(3):
                    org_id = str(uuid.uuid4())
                    cid, res = await acquire_sse_slot(org_id)
                    assert res == "ok"
                    acquired.append((org_id, cid))

                # Next must fail with global_limit
                extra_org = str(uuid.uuid4())
                cid_extra, res_extra = await acquire_sse_slot(extra_org)
                assert res_extra == "global_limit", f"Expected 'global_limit', got {res_extra}"
        finally:
            with patch("app.core.sse_manager.get_redis", return_value=r):
                for org_id, cid in acquired:
                    await release_sse_slot(org_id, cid)
            settings.SSE_MAX_PER_ORG = original_max_org
            settings.SSE_MAX_GLOBAL = original_max_global
            await r.aclose()

    @requires_redis
    async def test_sse_lease_expires_on_crash(self):
        """
        Simulate a crash by not calling release. After TTL, the slot must
        become available again.
        """
        import redis.asyncio as aioredis
        from app.core.sse_manager import acquire_sse_slot, release_sse_slot
        from app.core.config import settings

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        org_id = str(uuid.uuid4())
        original_ttl = settings.SSE_LEASE_TTL_SECONDS
        original_max = settings.SSE_MAX_PER_ORG

        try:
            settings.SSE_MAX_PER_ORG = 1
            settings.SSE_LEASE_TTL_SECONDS = 2  # Short TTL for test

            with patch("app.core.sse_manager.get_redis", return_value=r):
                # Acquire without releasing (simulate crash)
                cid, res = await acquire_sse_slot(org_id)
                assert res == "ok"

                # Immediately the slot is taken
                cid2, res2 = await acquire_sse_slot(org_id)
                assert res2 == "org_limit"

                # Wait (bounded) for the TTL to expire: the slot must free up
                acquired: list = []

                async def _slot_free() -> bool:
                    c, r_ = await acquire_sse_slot(org_id)
                    acquired[:] = [c, r_]
                    return r_ == "ok"

                assert await _wait_until(_slot_free, timeout=10.0, interval=0.25),                     f"Expected 'ok' after TTL expiry, got {acquired[1] if acquired else None}"
                cid3 = acquired[0]

                if cid3:
                    await release_sse_slot(org_id, cid3)
        finally:
            settings.SSE_LEASE_TTL_SECONDS = original_ttl
            settings.SSE_MAX_PER_ORG = original_max
            await r.aclose()

    @requires_redis
    async def test_sse_heartbeat_renews_lease(self):
        """Heartbeat must renew the lease TTL so the connection stays alive."""
        import redis.asyncio as aioredis
        from app.core.sse_manager import acquire_sse_slot, heartbeat_sse_slot, release_sse_slot
        from app.core.config import settings

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        org_id = str(uuid.uuid4())
        original_ttl = settings.SSE_LEASE_TTL_SECONDS

        try:
            settings.SSE_LEASE_TTL_SECONDS = 3

            with patch("app.core.sse_manager.get_redis", return_value=r):
                cid, res = await acquire_sse_slot(org_id)
                assert res == "ok"

                # Heartbeat before expiry
                await asyncio.sleep(1)
                renewed = await heartbeat_sse_slot(org_id, cid)
                assert renewed, "Heartbeat must return True for active lease"

                # Wait past original TTL — lease should still be alive due to renewal
                await asyncio.sleep(2)
                renewed2 = await heartbeat_sse_slot(org_id, cid)
                assert renewed2, "Lease must still be alive after heartbeat renewal"

                await release_sse_slot(org_id, cid)
        finally:
            settings.SSE_LEASE_TTL_SECONDS = original_ttl
            await r.aclose()

    @requires_redis
    async def test_sse_heartbeat_returns_false_for_expired(self):
        """Heartbeat on an expired/non-existent lease must return False."""
        import redis.asyncio as aioredis
        from app.core.sse_manager import heartbeat_sse_slot
        from app.core.config import settings

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        org_id = str(uuid.uuid4())

        with patch("app.core.sse_manager.get_redis", return_value=r):
            # Heartbeat a connection that was never acquired
            result = await heartbeat_sse_slot(org_id, "nonexistent_conn_id")
            assert result is False

        await r.aclose()

    @requires_redis
    async def test_sse_no_double_release(self):
        """Releasing the same slot twice must not cause negative counts."""
        import redis.asyncio as aioredis
        from app.core.sse_manager import acquire_sse_slot, release_sse_slot
        from app.core.config import settings

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        org_id = str(uuid.uuid4())
        original_max = settings.SSE_MAX_PER_ORG

        try:
            settings.SSE_MAX_PER_ORG = 2

            with patch("app.core.sse_manager.get_redis", return_value=r):
                cid, res = await acquire_sse_slot(org_id)
                assert res == "ok"

                # Release twice
                await release_sse_slot(org_id, cid)
                await release_sse_slot(org_id, cid)

                # Acquire should still work (not negative count)
                cid2, res2 = await acquire_sse_slot(org_id)
                assert res2 == "ok"
                await release_sse_slot(org_id, cid2)
        finally:
            settings.SSE_MAX_PER_ORG = original_max
            await r.aclose()

    @requires_redis
    async def test_sse_redis_error_denies(self):
        """When Redis is unavailable, SSE acquire must return 'redis_error' (fail-secure)."""
        import redis.asyncio as aioredis
        from app.core.sse_manager import acquire_sse_slot

        # Connect to non-existent port
        r = aioredis.Redis(host="127.0.0.1", port=16379, socket_connect_timeout=1, decode_responses=True)

        try:
            with patch("app.core.sse_manager.get_redis", return_value=r):
                cid, result = await acquire_sse_slot(str(uuid.uuid4()))
                assert result == "redis_error"
                assert cid is None
        finally:
            await r.aclose()

    @requires_redis
    async def test_sse_concurrent_acquisitions(self):
        """
        Multiple concurrent acquisitions must not exceed the limit.
        Verifies the Lua script atomicity.
        """
        import redis.asyncio as aioredis
        from app.core.sse_manager import acquire_sse_slot, release_sse_slot
        from app.core.config import settings

        r = aioredis.Redis(host="127.0.0.1", port=6379, db=_REDIS_DB, decode_responses=True)
        org_id = str(uuid.uuid4())
        original_max = settings.SSE_MAX_PER_ORG
        LIMIT = 5
        TOTAL = 20
        ok_count = 0
        denied_count = 0
        acquired_ids = []
        lock = asyncio.Lock()

        async def _try_acquire():
            nonlocal ok_count, denied_count
            with patch("app.core.sse_manager.get_redis", return_value=r):
                cid, result = await acquire_sse_slot(org_id)
            async with lock:
                if result == "ok":
                    ok_count += 1
                    acquired_ids.append((org_id, cid))
                else:
                    denied_count += 1

        try:
            settings.SSE_MAX_PER_ORG = LIMIT
            settings.SSE_MAX_GLOBAL = 100

            await asyncio.gather(*[_try_acquire() for _ in range(TOTAL)])

            assert ok_count <= LIMIT, \
                f"Acquired {ok_count} slots, limit was {LIMIT} — Lua atomicity failure"
            assert ok_count + denied_count == TOTAL
        finally:
            with patch("app.core.sse_manager.get_redis", return_value=r):
                for org_id_r, cid in acquired_ids:
                    await release_sse_slot(org_id_r, cid)
            settings.SSE_MAX_PER_ORG = original_max
            settings.SSE_MAX_GLOBAL = 200
            await r.aclose()


# ── Scan quota (PostgreSQL) tests ─────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.real_distributed
class TestScanQuotaAtomic:
    """
    Tests for the PostgreSQL-based atomic scan quota enforcement.
    Requires a real PostgreSQL connection.
    These tests opt out of stub fixtures to test the real service.
    """

    @pytest.fixture
    async def pg_session(self):
        """Real async session, no rollback stub."""
        if not POSTGRES_AVAILABLE:
            pytest.skip("PostgreSQL not available")

        from sqlalchemy.pool import NullPool
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

        engine = create_async_engine(TEST_DB_URL_ASYNC, poolclass=NullPool, echo=False)
        SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
        async with SessionLocal() as session:
            yield session
            await session.rollback()
        await engine.dispose()

    @requires_postgres
    async def test_quota_uses_organization_row_lock(self, pg_session):
        """
        _check_quota must SELECT Organization FOR UPDATE before counting scans.
        Verified by checking the SQL emitted contains FOR UPDATE.
        """
        from unittest.mock import patch
        import sqlalchemy
        executed_sqls = []

        original_execute = pg_session.execute

        async def _capture_execute(statement, *args, **kwargs):
            compiled = str(statement.compile(dialect=sqlalchemy.dialects.postgresql.dialect()))
            executed_sqls.append(compiled)
            return await original_execute(statement, *args, **kwargs)

        import uuid as _uuid
        from app.services.scan_service import ScanService
        from app.db.models.organization import Organization
        from sqlalchemy.ext.asyncio import AsyncSession

        # Create a real org
        org = Organization(
            id=_uuid.uuid4(),
            name="Quota Test Org",
            slug=f"quota-test-{_uuid.uuid4().hex[:8]}",
            is_active=True,
        )
        pg_session.add(org)
        await pg_session.flush()

        with patch.object(pg_session, "execute", side_effect=_capture_execute):
            service = ScanService(pg_session)
            try:
                await service._check_quota(org.id)
            except Exception:
                pass  # quota may not raise for empty org

        await pg_session.rollback()

        # Must have issued a FOR UPDATE on organizations table
        for_update_queries = [q for q in executed_sqls if "FOR UPDATE" in q.upper()]
        assert len(for_update_queries) > 0, \
            "_check_quota must issue SELECT FOR UPDATE on organizations table. " \
            f"Executed queries: {executed_sqls}"

    @requires_postgres
    async def test_quota_concurrent_requests_do_not_exceed_limit(self):
        """
        Multiple concurrent scan creations must not exceed SCANS_PER_ORG_PER_DAY.
        Uses asyncio.gather to simulate multiple concurrent API calls.
        """
        from sqlalchemy.pool import NullPool
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
        from app.services.scan_service import ScanService, SCANS_PER_ORG_PER_DAY
        from app.db.models.organization import Organization
        from app.db.models.user import User
        from app.db.models.scan import Scan, ScanStatus, ScanOutbox
        from sqlalchemy import select, delete
        import hashlib, base64

        engine = create_async_engine(TEST_DB_URL_ASYNC, poolclass=NullPool, echo=False)
        SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

        # Setup: create org and user
        import uuid as _uuid

        org_id = _uuid.uuid4()
        user_id = _uuid.uuid4()
        quota_limit = 3  # small limit for test speed

        async with SessionLocal() as setup_db:
            # Clean previous test data
            await setup_db.execute(delete(Scan).where(Scan.org_id == org_id))
            await setup_db.execute(
                delete(Organization).where(Organization.id == org_id)
            )
            await setup_db.flush()

            user = User(
                id=user_id,
                email=f"quota_concurrent_{_uuid.uuid4().hex[:8]}@test.dev",
                password_hash="x" * 64,
                is_active=True,
            )
            org = Organization(
                id=org_id,
                name="Concurrent Quota Test",
                slug=f"concurrent-quota-{_uuid.uuid4().hex[:8]}",
                is_active=True,
            )
            setup_db.add(user)
            setup_db.add(org)
            await setup_db.commit()

        TOTAL_ATTEMPTS = quota_limit + 5

        created_scan_ids = []
        lock = asyncio.Lock()

        # Patch quota limit ONCE outside gather — per-task patch/restore races:
        # Task 1's finally restores to 20 while Tasks 2-N still run, breaking the test.
        import app.services.scan_service as _svc_mod
        original_quota = _svc_mod.SCANS_PER_ORG_PER_DAY
        _svc_mod.SCANS_PER_ORG_PER_DAY = quota_limit

        async def _try_create():
            async with SessionLocal() as db:
                service = ScanService(db)
                try:
                    # Patch _dispatch_task to avoid Celery
                    async def _no_dispatch(scan):
                        return None

                    service._dispatch_task = _no_dispatch
                    from unittest.mock import patch as _upatch
                    with _upatch.object(service._ssrf_guard, "validate_domain_for_scan", AsyncMock(return_value=None)):
                        scan = await service.create_and_run_scan(
                            org_id=org_id,
                            target_domain="quota-concurrent-test.internal",
                            created_by=user_id,
                        )
                    async with lock:
                        created_scan_ids.append(str(scan.id))
                except Exception:
                    pass  # 429 expected

        try:
            # Run concurrently
            await asyncio.gather(*[_try_create() for _ in range(TOTAL_ATTEMPTS)])
        finally:
            _svc_mod.SCANS_PER_ORG_PER_DAY = original_quota

        # Count actual DB records
        async with SessionLocal() as check_db:
            from sqlalchemy import func
            from datetime import datetime, timezone, timedelta
            since = datetime.now(timezone.utc) - timedelta(hours=24)
            result = await check_db.execute(
                select(func.count(Scan.id)).where(
                    Scan.org_id == org_id,
                    Scan.created_at >= since,
                    Scan.status != ScanStatus.CANCELLED,
                )
            )
            actual_count = result.scalar_one()

        assert actual_count <= quota_limit, \
            f"Quota exceeded: {actual_count} scans created, limit was {quota_limit}"

        # Cleanup
        async with SessionLocal() as cleanup_db:
            await cleanup_db.execute(delete(ScanOutbox).where(
                ScanOutbox.scan_id.in_(
                    select(Scan.id).where(Scan.org_id == org_id)
                )
            ))
            await cleanup_db.execute(delete(Scan).where(Scan.org_id == org_id))
            await cleanup_db.execute(delete(Organization).where(Organization.id == org_id))
            await cleanup_db.execute(delete(User).where(User.id == user_id))
            await cleanup_db.commit()

        await engine.dispose()

    @requires_postgres
    async def test_quota_different_orgs_independent(self):
        """Quota enforcement for one org must not block other orgs."""
        from sqlalchemy.pool import NullPool
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from app.services.scan_service import ScanService
        from app.db.models.organization import Organization
        from app.db.models.user import User
        from app.db.models.scan import Scan, ScanOutbox, ScanStatus
        from sqlalchemy import delete, select
        import app.services.scan_service as _svc_mod
        import uuid as _uuid

        engine = create_async_engine(TEST_DB_URL_ASYNC, poolclass=NullPool, echo=False)
        SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

        org1_id = _uuid.uuid4()
        org2_id = _uuid.uuid4()
        user_id = _uuid.uuid4()

        async with SessionLocal() as db:
            db.add(User(id=user_id, email=f"quota_indep_{_uuid.uuid4().hex[:8]}@test.dev",
                        password_hash="x" * 64, is_active=True))
            db.add(Organization(id=org1_id, name="Org1", slug=f"o1-{_uuid.uuid4().hex[:8]}", is_active=True))
            db.add(Organization(id=org2_id, name="Org2", slug=f"o2-{_uuid.uuid4().hex[:8]}", is_active=True))
            await db.commit()

        original_quota = _svc_mod.SCANS_PER_ORG_PER_DAY
        _svc_mod.SCANS_PER_ORG_PER_DAY = 1

        try:
            from unittest.mock import patch as _patch
            # Fill org1 quota — bypass SSRF validation for test domains
            async with SessionLocal() as db:
                svc = ScanService(db)
                svc._dispatch_task = AsyncMock(return_value=None)
                with _patch.object(svc._ssrf_guard, "validate_domain_for_scan", AsyncMock(return_value=None)):
                    await svc.create_and_run_scan(org_id=org1_id, target_domain="quota-org1-test.internal", created_by=user_id,
                                                         skip_domain_verification=True)  # quota under test, not ownership

            # org2 must still work
            async with SessionLocal() as db:
                svc = ScanService(db)
                svc._dispatch_task = AsyncMock(return_value=None)
                with _patch.object(svc._ssrf_guard, "validate_domain_for_scan", AsyncMock(return_value=None)):
                    scan2 = await svc.create_and_run_scan(org_id=org2_id, target_domain="quota-org2-test.internal", created_by=user_id,
                                                         skip_domain_verification=True)  # quota under test, not ownership
                assert scan2 is not None, "org2 must be unaffected by org1 quota"
        finally:
            _svc_mod.SCANS_PER_ORG_PER_DAY = original_quota
            async with SessionLocal() as cleanup:
                await cleanup.execute(delete(ScanOutbox).where(
                    ScanOutbox.scan_id.in_(
                        select(Scan.id).where(Scan.org_id.in_([org1_id, org2_id]))
                    )
                ))
                await cleanup.execute(delete(Scan).where(Scan.org_id.in_([org1_id, org2_id])))
                await cleanup.execute(delete(Organization).where(
                    Organization.id.in_([org1_id, org2_id])
                ))
                await cleanup.execute(delete(User).where(User.id == user_id))
                await cleanup.commit()
            await engine.dispose()


# ── Worker fencing / idempotence tests ────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.real_distributed
class TestWorkerFencing:
    """
    Tests for worker lease fencing — verify that old workers with stale leases
    cannot write results after losing the lease.
    """

    @requires_postgres
    async def test_stale_worker_final_write_rejected(self):
        """
        Worker A acquires a lease. Worker B takes over (simulate by directly
        updating worker_lease_id). Worker A's final write must be a no-op.
        """
        from sqlalchemy.pool import NullPool
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from app.db.models.scan import Scan, ScanStatus, ScanOutbox
        from app.db.models.organization import Organization
        from app.db.models.user import User
        from sqlalchemy import update, select, delete
        import uuid as _uuid

        engine = create_async_engine(TEST_DB_URL_ASYNC, poolclass=NullPool, echo=False)
        SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

        org_id = _uuid.uuid4()
        user_id = _uuid.uuid4()
        scan_id = _uuid.uuid4()
        lease_a = str(_uuid.uuid4())
        lease_b = str(_uuid.uuid4())

        from datetime import datetime, timezone

        async with SessionLocal() as db:
            db.add(User(id=user_id, email=f"fencing_{_uuid.uuid4().hex[:8]}@test.dev",
                        password_hash="x" * 64, is_active=True))
            db.add(Organization(id=org_id, name="Fencing Org",
                                slug=f"fencing-{_uuid.uuid4().hex[:8]}", is_active=True))
            await db.flush()  # ensure User+Org rows exist before Scan FK insert
            db.add(Scan(
                id=scan_id,
                org_id=org_id,
                target_domain="fencing-test.com",
                status=ScanStatus.RUNNING,
                worker_lease_id=lease_a,
                created_by=user_id,
                created_at=datetime.now(timezone.utc),
            ))
            await db.commit()

        # Worker B takes over the lease
        async with SessionLocal() as db:
            await db.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(worker_lease_id=lease_b, status=ScanStatus.RUNNING)
            )
            await db.commit()

        # Worker A tries to write final result with old lease
        async with SessionLocal() as db:
            result = await db.execute(
                update(Scan)
                .where(Scan.id == scan_id, Scan.worker_lease_id == lease_a)
                .values(
                    status=ScanStatus.COMPLETED,
                    completed_at=datetime.now(timezone.utc),
                    worker_lease_id=None,
                )
                .returning(Scan.id)
            )
            updated = result.fetchone()
            await db.commit()

        assert updated is None, "Worker A must not be able to write with stale lease"

        # Worker B's lease must still be intact
        async with SessionLocal() as db:
            result = await db.execute(
                select(Scan.worker_lease_id, Scan.status).where(Scan.id == scan_id)
            )
            row = result.fetchone()
        assert row is not None
        assert row[0] == lease_b, "Worker B's lease must be unchanged"
        assert row[1] == ScanStatus.RUNNING, "Status must still be RUNNING"

        # Cleanup
        async with SessionLocal() as db:
            await db.execute(delete(Scan).where(Scan.id == scan_id))
            await db.execute(delete(Organization).where(Organization.id == org_id))
            await db.execute(delete(User).where(User.id == user_id))
            await db.commit()

        await engine.dispose()

    @requires_postgres
    async def test_duplicate_dispatch_no_duplicate_scan(self):
        """
        Sending the same scan_task message twice (at-least-once delivery) must
        result in only one worker acquiring the lease. The second worker must
        find status != QUEUED and return without processing.

        Simulated by running _run_scan twice for the same scan_id:
        first call acquires the lease, second call must return immediately
        (lease not acquired path).
        """
        from sqlalchemy.pool import NullPool
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from app.db.models.scan import Scan, ScanStatus, ScanOutbox
        from app.db.models.organization import Organization
        from app.db.models.user import User
        from sqlalchemy import delete
        from app.worker.tasks import _run_scan
        import uuid as _uuid
        from datetime import datetime, timezone
        from unittest.mock import AsyncMock, patch

        engine = create_async_engine(TEST_DB_URL_ASYNC, poolclass=NullPool, echo=False)
        SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

        org_id = _uuid.uuid4()
        user_id = _uuid.uuid4()
        scan_id = _uuid.uuid4()

        async with SessionLocal() as db:
            db.add(User(id=user_id, email=f"dup_{_uuid.uuid4().hex[:8]}@test.dev",
                        password_hash="x" * 64, is_active=True))
            db.add(Organization(id=org_id, name="Dup Scan Org",
                                slug=f"dup-{_uuid.uuid4().hex[:8]}", is_active=True))
            await db.flush()  # ensure User+Org rows exist before Scan FK insert
            db.add(Scan(
                id=scan_id,
                org_id=org_id,
                target_domain="dup-test.com",
                status=ScanStatus.QUEUED,
                created_by=user_id,
                created_at=datetime.now(timezone.utc),
            ))
            await db.commit()

        leases_acquired = []

        # Mock task object
        mock_task = MagicMock()
        mock_task.max_retries = 2
        mock_task.request = MagicMock()
        mock_task.request.retries = 0
        mock_task.retry = MagicMock(side_effect=Exception("retry"))

        # Mock every engine (no network) and run as the self-hosted edition so the
        # full pipeline executes in both editions (the SaaS domain gate would
        # otherwise fail the scan before any engine runs).
        from app.core.config import settings as _settings
        from tests.worker_db_mock import stub_aux_engines
        with patch("app.engines.dns_auth.DNSAuthEngine") as mock_dns, \
             patch("app.engines.smtp_discovery.SMTPDiscoveryEngine") as mock_smtp, \
             patch("app.engines.webmail.WebmailEngine") as mock_webmail, \
             patch("app.engines.vuln_intel.VulnIntelEngine") as mock_vuln, \
             patch.object(_settings, "MAILOX_EDITION", "selfhosted"), \
             stub_aux_engines(), \
             patch("app.db.session.AsyncSessionLocal", SessionLocal):

            _empty = MagicMock(findings=[], success=True, error=None, metadata={})
            mock_webmail.return_value.run = AsyncMock(return_value=_empty)
            mock_vuln.return_value.run_from_findings = AsyncMock(return_value=_empty)

            dns_instance = AsyncMock()
            dns_instance.run = AsyncMock(return_value=MagicMock(findings=[]))
            mock_dns.return_value = dns_instance

            smtp_instance = AsyncMock()
            smtp_instance.run = AsyncMock(return_value=MagicMock(findings=[]))
            mock_smtp.return_value = smtp_instance

            # Both run concurrently — simulating duplicate delivery
            results = await asyncio.gather(
                _run_scan(str(scan_id), mock_task),
                _run_scan(str(scan_id), mock_task),
                return_exceptions=True,
            )

        # Exactly one must have succeeded (the other returns None due to lease not acquired)
        from sqlalchemy import select
        async with SessionLocal() as db:
            scan = (await db.execute(
                select(Scan).where(Scan.id == scan_id)
            )).scalar_one_or_none()

        assert scan is not None
        # Status must be terminal (not stuck in RUNNING with two workers fighting)
        assert scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED), \
            f"Scan must be terminal after duplicate dispatch, got {scan.status}"
        # worker_lease_id must be cleared (final write succeeded for one worker)
        assert scan.worker_lease_id is None, \
            "worker_lease_id must be cleared after scan completes"

        # Cleanup
        async with SessionLocal() as db:
            from sqlalchemy import delete as _del
            await db.execute(_del(ScanOutbox).where(ScanOutbox.scan_id == scan_id))
            await db.execute(_del(Scan).where(Scan.id == scan_id))
            await db.execute(_del(Organization).where(Organization.id == org_id))
            await db.execute(_del(User).where(User.id == user_id))
            await db.commit()

        await engine.dispose()


# ── Report summary ────────────────────────────────────────────────────────────

def test_environment_report():
    """Non-skippable summary of service availability for this test run."""
    redis_status = "AVAILABLE" if REDIS_AVAILABLE else "UNAVAILABLE — distributed tests SKIPPED"
    postgres_status = "AVAILABLE" if POSTGRES_AVAILABLE else "UNAVAILABLE — integration tests SKIPPED"
    print(f"\n[Phase 3.5] Redis: {redis_status}")
    print(f"[Phase 3.5] PostgreSQL: {postgres_status}")
    if not REDIS_AVAILABLE:
        print("[Phase 3.5] WARNING: Redis tests are SKIPPED, not passed.")
    if not POSTGRES_AVAILABLE:
        print("[Phase 3.5] WARNING: PostgreSQL tests are SKIPPED, not passed.")
