"""
Shared async Redis client for MAILOX application-level operations.

Distinct from Celery's Redis connection — this client is used by:
- Distributed rate limiter (deps.py)
- Distributed SSE lease manager (sse_manager.py)

Uses redis.asyncio (bundled with redis>=4.2).
"""
import redis.asyncio as aioredis

from app.core.config import settings

_redis_pool: aioredis.ConnectionPool | None = None
_redis_client: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    """Return the shared async Redis client, creating it on first call."""
    global _redis_pool, _redis_client
    if _redis_client is None:
        _redis_pool = aioredis.ConnectionPool.from_url(
            settings.REDIS_URL,
            max_connections=20,
            decode_responses=True,
        )
        _redis_client = aioredis.Redis(connection_pool=_redis_pool)
    return _redis_client


async def close_redis() -> None:
    """Close the shared Redis client (call on app shutdown)."""
    global _redis_client, _redis_pool
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
    if _redis_pool is not None:
        await _redis_pool.aclose()
        _redis_pool = None
