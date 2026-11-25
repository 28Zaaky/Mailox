"""
Distributed SSE connection lease manager backed by Redis ZSET.

Design:
  Each connection holds a lease identified by a unique connection_id.
  Leases are stored as ZSET members with score = expiry_unix_ms.
  Stale entries (score < now) are automatically excluded from counts.

  Two ZSET keys per connection:
    sse:org:{org_id}    — per-org connection count
    sse:global          — global connection count

Acquire (Lua, atomic):
  1. ZREMRANGEBYSCORE to prune expired entries in both keys
  2. ZCARD both keys; if either >= limit → reject
  3. ZADD both keys with new entry at score=expiry

Release (Lua, atomic):
  1. ZREM from both keys

Heartbeat:
  ZADD NX=false XX=true (update-only) with new expiry score.
  If the lease was not renewed, the entry naturally expires and
  is excluded from future counts — provides crash safety.

Error handling:
  On Redis error during acquire: DENY (fail-secure, return "redis_error")
  On Redis error during release: log and continue (graceful degradation)
  On Redis error during heartbeat: log and continue

Crash safety:
  Lease TTL = SSE_LEASE_TTL_SECONDS (default: 90s).
  Heartbeat interval = SSE_HEARTBEAT_INTERVAL_SECONDS (default: 20s).
  A crashed worker stops heartbeating → lease expires in TTL seconds.
  During that window the slot is counted as occupied (conservative).
"""
import time
import uuid as _uuid_module

import structlog

from app.core.config import settings
from app.core.redis_client import get_redis

logger = structlog.get_logger("mailox.sse_manager")

_ORG_KEY_PREFIX = "sse:org:"
_GLOBAL_KEY = "sse:global"

# Lua: acquire two ZSET slots atomically
# KEYS[1] = org key, KEYS[2] = global key
# ARGV[1] = now_ms, ARGV[2] = expiry_ms (score)
# ARGV[3] = org_limit, ARGV[4] = global_limit
# ARGV[5] = connection_id (member)
# Returns: "ok" | "org_limit" | "global_limit"
_ACQUIRE_LUA = """
local org_key = KEYS[1]
local global_key = KEYS[2]
local now = tonumber(ARGV[1])
local expiry = tonumber(ARGV[2])
local org_limit = tonumber(ARGV[3])
local global_limit = tonumber(ARGV[4])
local conn_id = ARGV[5]

redis.call('ZREMRANGEBYSCORE', org_key, '-inf', now - 1)
redis.call('ZREMRANGEBYSCORE', global_key, '-inf', now - 1)

local org_count = redis.call('ZCARD', org_key)
if org_count >= org_limit then
    return 'org_limit'
end

local global_count = redis.call('ZCARD', global_key)
if global_count >= global_limit then
    return 'global_limit'
end

redis.call('ZADD', org_key, expiry, conn_id)
redis.call('ZADD', global_key, expiry, conn_id)
redis.call('EXPIRE', org_key, math.ceil((expiry - now) / 1000) + 10)
redis.call('EXPIRE', global_key, math.ceil((expiry - now) / 1000) + 10)
return 'ok'
"""

# Lua: release both ZSET slots atomically
# KEYS[1] = org key, KEYS[2] = global key, ARGV[1] = connection_id
_RELEASE_LUA = """
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('ZREM', KEYS[2], ARGV[1])
return 1
"""

# Lua: heartbeat — update expiry if connection still exists
# KEYS[1] = org key, KEYS[2] = global key
# ARGV[1] = new_expiry_ms, ARGV[2] = connection_id
# Returns: 1 if renewed, 0 if lease not found (already expired)
_HEARTBEAT_LUA = """
local org_exists = redis.call('ZSCORE', KEYS[1], ARGV[2])
if not org_exists then
    return 0
end
redis.call('ZADD', KEYS[1], tonumber(ARGV[1]), ARGV[2])
redis.call('ZADD', KEYS[2], tonumber(ARGV[1]), ARGV[2])
return 1
"""


def new_connection_id() -> str:
    return _uuid_module.uuid4().hex


async def acquire_sse_slot(org_id: str) -> tuple[str, str] | tuple[None, str]:
    """
    Try to acquire an SSE connection slot.

    Returns:
        (connection_id, "ok") on success
        (None, "org_limit") if org limit reached
        (None, "global_limit") if global limit reached
        (None, "redis_error") if Redis unavailable
    """
    org_key = f"{_ORG_KEY_PREFIX}{org_id}"
    conn_id = new_connection_id()
    now_ms = int(time.time() * 1000)
    expiry_ms = now_ms + settings.SSE_LEASE_TTL_SECONDS * 1000

    redis = get_redis()
    try:
        result = await redis.eval(
            _ACQUIRE_LUA,
            2,
            org_key,
            _GLOBAL_KEY,
            now_ms,
            expiry_ms,
            settings.SSE_MAX_PER_ORG,
            settings.SSE_MAX_GLOBAL,
            conn_id,
        )
    except Exception as exc:
        logger.error("sse_acquire_redis_error", org_id=org_id, error=type(exc).__name__)
        return None, "redis_error"

    if result == "ok":
        return conn_id, "ok"
    return None, result


async def release_sse_slot(org_id: str, conn_id: str) -> None:
    """Release an SSE connection slot. Logs errors but does not raise."""
    org_key = f"{_ORG_KEY_PREFIX}{org_id}"
    redis = get_redis()
    try:
        await redis.eval(_RELEASE_LUA, 2, org_key, _GLOBAL_KEY, conn_id)
    except Exception as exc:
        logger.error(
            "sse_release_redis_error",
            org_id=org_id,
            conn_id=conn_id,
            error=type(exc).__name__,
        )


async def heartbeat_sse_slot(org_id: str, conn_id: str) -> bool:
    """
    Renew the SSE lease TTL.

    Returns True if the lease was renewed, False if it had already expired.
    Logs errors but does not raise.
    """
    org_key = f"{_ORG_KEY_PREFIX}{org_id}"
    now_ms = int(time.time() * 1000)
    new_expiry_ms = now_ms + settings.SSE_LEASE_TTL_SECONDS * 1000

    redis = get_redis()
    try:
        result = await redis.eval(
            _HEARTBEAT_LUA,
            2,
            org_key,
            _GLOBAL_KEY,
            new_expiry_ms,
            conn_id,
        )
        return int(result) == 1
    except Exception as exc:
        logger.warning(
            "sse_heartbeat_redis_error",
            org_id=org_id,
            conn_id=conn_id,
            error=type(exc).__name__,
        )
        return False
