"""
Webhook dispatch helper — fire all matching enabled webhooks for an org/event.
Best-effort: failures are logged but never propagate to the caller.
"""
import asyncio
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import structlog
from sqlalchemy import select, update

from app.db.models.webhook import WebhookConfig, WebhookEvent
from app.db.session import AsyncSessionLocal
from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError
from app.engines.webmail_transport import PinnedDNSTransport

logger = structlog.get_logger("mailox.webhooks")


_WEBHOOK_TIMEOUT = 8.0


async def is_safe_webhook_url(url: str, guard: Optional[SSRFGuard] = None) -> tuple[bool, str]:
    """Returns (is_safe, reason). Blocks SSRF destinations.

    Resolution goes through SSRFGuard (async, trusted resolvers, every A/AAAA
    record checked against the full blocklist incl. 0.0.0.0/8, ::, multicast,
    reserved, metadata). This is a pre-check for a clean error message only:
    the actual connection is pinned by PinnedDNSTransport, which re-validates
    and connects to the validated IP, so a rebinding answer cannot slip in.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "invalid URL"
    if parsed.scheme not in ("http", "https"):
        return False, "scheme must be http or https"
    try:
        hostname = (parsed.hostname or "").rstrip(".").lower()
        parsed.port  # raises ValueError on a bogus port
    except ValueError:
        return False, "invalid URL"
    if not hostname:
        return False, "missing hostname"
    if parsed.username or parsed.password:
        return False, "credentials in URL not allowed"
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        return False, "internal hostname"
    try:
        await (guard or SSRFGuard()).resolve_and_validate(hostname)
    except SSRFGuardError as exc:
        return False, str(exc)
    return True, ""


def build_webhook_client(guard: Optional[SSRFGuard] = None) -> httpx.AsyncClient:
    """httpx client whose every TCP connect is pinned to an SSRF-validated IP.

    - PinnedDNSTransport: the OS resolver is never used, no DNS-rebinding window
    - follow_redirects=False: a 3xx is returned as-is, never followed
    - trust_env=False: HTTP(S)_PROXY env vars cannot route the request elsewhere
    """
    transport = PinnedDNSTransport(ssrf_guard=guard or SSRFGuard(), verify=True)
    return httpx.AsyncClient(
        transport=transport,
        timeout=_WEBHOOK_TIMEOUT,
        follow_redirects=False,
        trust_env=False,
    )


async def post_webhook(url: str, body: str, headers: dict[str, str]) -> httpx.Response:
    """Validate then POST a webhook. Raises SSRFGuardError if the target is blocked."""
    guard = SSRFGuard()
    safe, reason = await is_safe_webhook_url(url, guard)
    if not safe:
        raise SSRFGuardError(reason)

    async def _send() -> httpx.Response:
        # stream() + no body read: a tenant endpoint cannot make us buffer a
        # huge response. Only status/headers are consumed by callers.
        async with build_webhook_client(guard) as client:
            async with client.stream("POST", url, content=body, headers=headers) as resp:
                return resp

    # httpx timeouts are per-operation; bound the whole delivery as well.
    return await asyncio.wait_for(_send(), timeout=_WEBHOOK_TIMEOUT)


def _get_hmac_secret(cfg: WebhookConfig) -> bytes | None:
    """Decrypt secret_enc and return bytes, or None if unset."""
    if not cfg.secret_enc:
        return None
    try:
        from app.core.encryption import decrypt_secret
        return decrypt_secret(cfg.secret_enc).encode()
    except Exception:
        return None


async def dispatch_webhooks(
    org_id: uuid.UUID,
    event: WebhookEvent,
    payload: dict[str, Any],
) -> None:
    """POST to all enabled webhook URLs for org_id that subscribe to event.

    Updates last_triggered_at and last_status_code on each config after delivery.
    Errors are caught per-webhook so one bad URL never blocks others.
    SSRF-protected: every resolved IP is validated by SSRFGuard and the TCP
    connection is pinned to the validated IP (no DNS-rebinding window).
    Redirects are NOT followed to prevent redirect-based SSRF.
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(WebhookConfig).where(
                WebhookConfig.org_id == org_id,
                WebhookConfig.enabled == True,  # noqa: E712
            )
        )
        configs = result.scalars().all()

    for cfg in configs:
        if event.value not in (cfg.events or []):
            continue

        try:
            body = json.dumps(
                {"event": event.value, "timestamp": time.time(), **payload},
                default=str,
            )
            headers: dict[str, str] = {
                "Content-Type": "application/json",
                "X-Mailox-Event": event.value,
            }
            secret_bytes = _get_hmac_secret(cfg)
            if secret_bytes:
                sig = hmac.new(secret_bytes, body.encode(), hashlib.sha256).hexdigest()
                headers["X-Mailox-Signature"] = f"sha256={sig}"

            # DNS-pinned, no redirects, no env proxies (see build_webhook_client)
            resp = await post_webhook(cfg.url, body, headers)

            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(WebhookConfig)
                    .where(WebhookConfig.id == cfg.id)
                    .values(
                        last_triggered_at=datetime.now(timezone.utc),
                        last_status_code=resp.status_code,
                    )
                )
                await db.commit()

            logger.info(
                "webhook_fired",
                url=cfg.url,
                event=event.value,
                status=resp.status_code,
            )
        except SSRFGuardError as exc:
            # SSRF guard — validated (and DNS-pinned) before any connection attempt
            logger.warning("webhook_ssrf_blocked", url=cfg.url, reason=str(exc))
        except Exception as exc:
            logger.warning(
                "webhook_failed", url=cfg.url, event=event.value, error_type=type(exc).__name__
            )
