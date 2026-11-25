"""
Webhook configuration API — per-org HTTP callbacks on scan/finding events.

POST   /orgs/{org_id}/webhooks              create webhook
GET    /orgs/{org_id}/webhooks              list webhooks for org
PATCH  /orgs/{org_id}/webhooks/{id}         update (url, events, enabled, secret)
DELETE /orgs/{org_id}/webhooks/{id}         delete
POST   /orgs/{org_id}/webhooks/{id}/test    send test ping
"""
import json
import time
import uuid
from typing import List

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_verified_org
from app.core.encryption import decrypt_secret, encrypt_secret
from app.db.models.webhook import WebhookConfig, WebhookEvent
from app.engines.ssrf_guard import SSRFGuardError
from app.worker.webhook_dispatch import is_safe_webhook_url, post_webhook
from app.db.session import get_db
from app.schemas.webhook import WebhookCreate, WebhookResponse, WebhookUpdate

logger = structlog.get_logger("mailox.webhooks")

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


async def _get_webhook_or_404(
    db: AsyncSession,
    org_id: uuid.UUID,
    webhook_id: uuid.UUID,
) -> WebhookConfig:
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.id == webhook_id,
            WebhookConfig.org_id == org_id,
        )
    )
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return wh


@router.post(
    "",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def create_webhook(
    org_id: uuid.UUID,
    body: WebhookCreate,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> WebhookResponse:
    safe, reason = await is_safe_webhook_url(body.url)
    if not safe:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Webhook URL blocked by SSRF policy: {reason}",
        )
    wh = WebhookConfig(
        id=uuid.uuid4(),
        org_id=verified_org,
        url=body.url,
        events=body.events,
        secret_enc=encrypt_secret(body.secret) if body.secret else None,
        enabled=True,
    )
    db.add(wh)
    await db.commit()
    await db.refresh(wh)
    return WebhookResponse.model_validate(wh)


@router.get(
    "",
    response_model=List[WebhookResponse],
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def list_webhooks(
    org_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[WebhookResponse]:
    result = await db.execute(
        select(WebhookConfig)
        .where(WebhookConfig.org_id == verified_org)
        .order_by(WebhookConfig.created_at.desc())
    )
    webhooks = result.scalars().all()
    return [WebhookResponse.model_validate(w) for w in webhooks]


@router.patch(
    "/{webhook_id}",
    response_model=WebhookResponse,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def update_webhook(
    org_id: uuid.UUID,
    webhook_id: uuid.UUID,
    body: WebhookUpdate,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> WebhookResponse:
    wh = await _get_webhook_or_404(db, verified_org, webhook_id)
    if body.url is not None:
        safe, reason = await is_safe_webhook_url(body.url)
        if not safe:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Webhook URL blocked by SSRF policy: {reason}",
            )
        wh.url = body.url
    if body.events is not None:
        wh.events = body.events
    if body.enabled is not None:
        wh.enabled = body.enabled
    if body.secret is not None:
        wh.secret_enc = encrypt_secret(body.secret) if body.secret else None
    await db.commit()
    await db.refresh(wh)
    return WebhookResponse.model_validate(wh)


@router.delete(
    "/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def delete_webhook(
    org_id: uuid.UUID,
    webhook_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    wh = await _get_webhook_or_404(db, verified_org, webhook_id)
    await db.delete(wh)
    await db.commit()


@router.post(
    "/{webhook_id}/test",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def test_webhook(
    org_id: uuid.UUID,
    webhook_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    wh = await _get_webhook_or_404(db, verified_org, webhook_id)
    safe, reason = await is_safe_webhook_url(wh.url)
    if not safe:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Webhook URL blocked by SSRF policy: {reason}",
        )
    payload = json.dumps({
        "event": "ping",
        "timestamp": time.time(),
        "webhook_id": str(wh.id),
        "org_id": str(wh.org_id),
        "message": "MAILOX webhook test",
    })
    headers = {
        "Content-Type": "application/json",
        "X-Mailox-Event": "ping",
    }
    if wh.secret_enc:
        import hashlib
        import hmac as _hmac
        secret_bytes = decrypt_secret(wh.secret_enc).encode()
        sig = _hmac.new(secret_bytes, payload.encode(), hashlib.sha256).hexdigest()
        headers["X-Mailox-Signature"] = f"sha256={sig}"

    # DNS-pinned to the validated IP, no redirects, no env proxies
    try:
        resp = await post_webhook(wh.url, payload, headers)
        return {"status_code": resp.status_code, "ok": resp.is_success}
    except SSRFGuardError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Webhook URL blocked by SSRF policy",
        )
    except Exception as exc:
        # Never echo exception text: it can leak internal hostnames/IPs/ports
        logger.warning("webhook_test_failed", webhook_id=str(wh.id), error_type=type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Webhook delivery failed",
        )
