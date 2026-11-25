"""
Distributed Redis sliding-window rate limiter.

Design:
- Each key = "rl:{route_category}:{client_identity}"
- Sliding window via Redis ZSET: member="{now_ms}:{uuid}", score=now_ms
- Lua script ensures atomicity (remove stale + count + add in one RTT)
- On Redis error: DENY request (fail-secure, logged)
- IP extraction: respects TRUSTED_PROXY_COUNT to handle X-Forwarded-For
  correctly; never trusts client-supplied header when TRUSTED_PROXY_COUNT=0

Fail-secure rationale:
  An unavailable Redis means no distributed rate state is available.
  Silently falling back to unlimited access would allow an attacker to
  trigger Redis downtime to bypass rate limiting. We deny instead and
  return 503 with Retry-After, which is consistent with the security
  posture of this application.
"""
import ipaddress
import time
import uuid as _uuid

import structlog
from fastapi import HTTPException, Request, status

from app.core.config import settings
from app.core.redis_client import get_redis

logger = structlog.get_logger("mailox.rate_limiter")

# Lua sliding-window script.
# KEYS[1] = rate limit key
# ARGV[1] = now_ms (current time as integer milliseconds)
# ARGV[2] = window_ms (window size in milliseconds)
# ARGV[3] = limit (max requests per window)
# ARGV[4] = member (unique member for this call: "now_ms:uuid4")
# Returns: 0 = rate-limited, 1 = allowed
_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
    return 0
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window / 1000) + 2)
return 1
"""


def _extract_client_ip(request: Request) -> str:
    """
    Extract the client IP respecting TRUSTED_PROXY_COUNT.

    If TRUSTED_PROXY_COUNT=0: use request.client.host (direct connection)
    If TRUSTED_PROXY_COUNT=N: take the Nth-from-right non-empty IP in
        X-Forwarded-For. If the header is absent or malformed, fall back to
        request.client.host.

    Rejects private/loopback IPs that arrive via X-Forwarded-For when
    no trusted proxy is configured — this prevents header injection from
    localhost-adjacent sources.
    """
    if settings.TRUSTED_PROXY_COUNT <= 0:
        return request.client.host if request.client else "unknown"

    xff = request.headers.get("X-Forwarded-For", "")
    parts = [p.strip() for p in xff.split(",") if p.strip()]

    # Take the Nth-from-right, where N=TRUSTED_PROXY_COUNT (1-indexed)
    target_index = len(parts) - settings.TRUSTED_PROXY_COUNT
    if target_index >= 0 and parts:
        candidate = parts[target_index]
        try:
            addr = ipaddress.ip_address(candidate)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                # Suspicious — a legitimate client IP should never be private
                # when arriving through a trusted proxy
                logger.warning(
                    "rate_limit_suspicious_xff",
                    xff=xff,
                    candidate=candidate,
                )
                return request.client.host if request.client else "unknown"
            return candidate
        except ValueError:
            pass

    return request.client.host if request.client else "unknown"


async def check_rate_limit(
    request: Request,
    route_category: str,
    limit: int,
    window_seconds: int = 60,
) -> None:
    """
    Raise HTTP 429 if the client has exceeded the rate limit.

    Args:
        request: FastAPI request (for IP extraction)
        route_category: Short string identifying the route group (e.g. "auth")
        limit: Max requests per window
        window_seconds: Sliding window size in seconds

    Raises:
        HTTPException 429 if rate limited
        HTTPException 503 if Redis is unavailable (fail-secure)
    """
    client_ip = _extract_client_ip(request)
    key = f"rl:{route_category}:{client_ip}"
    now_ms = int(time.time() * 1000)
    window_ms = window_seconds * 1000
    member = f"{now_ms}:{_uuid.uuid4().hex[:8]}"

    redis = get_redis()
    try:
        result = await redis.eval(
            _SLIDING_WINDOW_LUA,
            1,            # numkeys
            key,          # KEYS[1]
            now_ms,       # ARGV[1]
            window_ms,    # ARGV[2]
            limit,        # ARGV[3]
            member,       # ARGV[4]
        )
    except Exception as exc:
        logger.error(
            "rate_limit_redis_error",
            route=route_category,
            ip=client_ip,
            error=type(exc).__name__,
        )
        # Fail-secure: Redis down → deny to prevent bypass
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service unavailable",
            headers={"Retry-After": "30"},
        )

    if result == 0:
        logger.warning(
            "rate_limit_exceeded",
            route=route_category,
            ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(window_seconds)},
        )
