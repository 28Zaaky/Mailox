"""
Org-level settings — per-org API keys and scan preferences.

GET  /orgs/{org_id}/settings   — read current settings (admin/owner only)
PATCH /orgs/{org_id}/settings  — upsert settings (admin/owner only)
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_verified_org
from app.core.encryption import decrypt_secret, encrypt_secret
from app.db.models.org_settings import OrgSettings
from app.db.session import get_db
from app.schemas.org_settings import OrgSettingsResponse, OrgSettingsUpdate

router = APIRouter(prefix="/settings", tags=["org-settings"])


def _build_response(row: OrgSettings) -> OrgSettingsResponse:
    return OrgSettingsResponse(
        org_id=row.org_id,
        github_token_set=bool(row.github_token_enc),
        intelx_api_key_set=bool(row.intelx_api_key_enc),
        nvd_api_key_set=bool(row.nvd_api_key_enc),
        canary_email=row.canary_email,
        cred_probe_enabled=row.cred_probe_enabled,
        scan_timeout_seconds=row.scan_timeout_seconds,
        updated_at=row.updated_at,
    )


async def _get_or_create(db: AsyncSession, org_id: uuid.UUID) -> OrgSettings:
    result = await db.execute(
        select(OrgSettings).where(OrgSettings.org_id == org_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        row = OrgSettings(
            id=uuid.uuid4(),
            org_id=org_id,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


@router.get(
    "",
    response_model=OrgSettingsResponse,
    dependencies=[Depends(RequirePermission("org:write"))],
)
async def get_org_settings(
    org_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> OrgSettingsResponse:
    row = await _get_or_create(db, verified_org)
    return _build_response(row)


@router.patch(
    "",
    response_model=OrgSettingsResponse,
    dependencies=[Depends(RequirePermission("org:write"))],
)
async def update_org_settings(
    org_id: uuid.UUID,
    body: OrgSettingsUpdate,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> OrgSettingsResponse:
    row = await _get_or_create(db, verified_org)

    # Encrypt API keys if provided
    if body.github_token is not None:
        if body.github_token == "":
            row.github_token_enc = None
        else:
            try:
                row.github_token_enc = encrypt_secret(body.github_token)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to encrypt github_token: {exc}",
                )

    if body.intelx_api_key is not None:
        if body.intelx_api_key == "":
            row.intelx_api_key_enc = None
        else:
            try:
                row.intelx_api_key_enc = encrypt_secret(body.intelx_api_key)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to encrypt intelx_api_key: {exc}",
                )

    if body.nvd_api_key is not None:
        if body.nvd_api_key == "":
            row.nvd_api_key_enc = None
        else:
            try:
                row.nvd_api_key_enc = encrypt_secret(body.nvd_api_key)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to encrypt nvd_api_key: {exc}",
                )

    # Plain fields
    if body.canary_email is not None:
        row.canary_email = body.canary_email or None

    if body.cred_probe_enabled is not None:
        row.cred_probe_enabled = body.cred_probe_enabled

    if body.scan_timeout_seconds is not None:
        if body.scan_timeout_seconds < 30 or body.scan_timeout_seconds > 600:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="scan_timeout_seconds must be between 30 and 600",
            )
        row.scan_timeout_seconds = body.scan_timeout_seconds

    row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(row)
    return _build_response(row)
