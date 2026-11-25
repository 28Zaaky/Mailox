import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user
from app.core.rate_limiter import _extract_client_ip, check_rate_limit
from app.db.models.audit import AuditLog
from app.db.models.organization import ROLE_PERMISSIONS, Organization, OrganizationMember
from app.db.models.scan import FindingStatus, RiskLevel, Scan, ScanFinding, ScanStatus
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.organization import (
    AuditLogListResponse,
    AuditLogResponse,
    CreateOrganizationRequest,
    InviteMemberRequest,
    MemberResponse,
    OrgStatsResponse,
    OrganizationResponse,
    UpdateOrgRequest,
)
from app.services.organization_service import OrganizationService

router = APIRouter(prefix="/orgs", tags=["organizations"])


async def _member_roles(
    db: AsyncSession, user: User, org_ids: List[uuid.UUID]
) -> dict[uuid.UUID, str]:
    """Active role of `user` in each of `org_ids` (missing key = not a member)."""
    if not org_ids:
        return {}
    rows = (await db.execute(
        select(OrganizationMember.org_id, OrganizationMember.role).where(
            OrganizationMember.user_id == user.id,
            OrganizationMember.org_id.in_(org_ids),
            OrganizationMember.is_active == True,  # noqa: E712
        )
    )).all()
    return {org_id: (role.value if hasattr(role, "value") else str(role)) for org_id, role in rows}


def _role_for(roles: dict[uuid.UUID, str], org_id: uuid.UUID, user: User) -> Optional[str]:
    role = roles.get(org_id)
    if role is None and user.sees_all_orgs:
        return "platform_admin"
    return role


def _role_has(role: Optional[str], permission: str) -> bool:
    if role is None:
        return False
    perms = ROLE_PERMISSIONS.get(role)
    if perms is None:
        # ROLE_PERMISSIONS is keyed by OrgRole members (str enum) and plain strings
        perms = next((v for k, v in ROLE_PERMISSIONS.items() if str(getattr(k, "value", k)) == role), set())
    return "*" in perms or permission in perms


async def _org_response(db: AsyncSession, org: Organization, user: User) -> OrganizationResponse:
    resp = OrganizationResponse.model_validate(org)
    roles = await _member_roles(db, user, [org.id])
    resp.current_user_role = _role_for(roles, org.id, user)
    return resp


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    body: CreateOrganizationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrganizationResponse:
    service = OrganizationService(db)
    org = await service.create_organization(body.name, body.get_slug(), current_user)
    return await _org_response(db, org, current_user)


@router.get("", response_model=List[OrganizationResponse])
async def list_organizations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[OrganizationResponse]:
    service = OrganizationService(db)
    orgs = await service.list_user_organizations(current_user)
    roles = await _member_roles(db, current_user, [o.id for o in orgs])
    out = []
    for o in orgs:
        resp = OrganizationResponse.model_validate(o)
        resp.current_user_role = _role_for(roles, o.id, current_user)
        out.append(resp)
    return out


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrganizationResponse:
    service = OrganizationService(db)
    org = await service.get_organization(org_id, current_user)
    return await _org_response(db, org, current_user)


@router.get("/{org_id}/members", response_model=List[MemberResponse])
async def list_members(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[MemberResponse]:
    service = OrganizationService(db)
    pairs = await service.list_members(org_id, current_user)
    result = []
    for membership, user in pairs:
        resp = MemberResponse.model_validate(membership)
        resp.email = user.email
        resp.full_name = getattr(user, "full_name", None)
        resp.joined_at = membership.created_at
        result.append(resp)
    return result


@router.post("/{org_id}/members/invite", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
async def invite_member(
    org_id: uuid.UUID,
    body: InviteMemberRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MemberResponse:
    service = OrganizationService(db)
    membership, user = await service.add_member(org_id, body.email, body.role, current_user)
    resp = MemberResponse.model_validate(membership)
    resp.email = user.email
    resp.full_name = getattr(user, "full_name", None)
    resp.joined_at = membership.created_at
    return resp


@router.delete("/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    service = OrganizationService(db)
    await service.remove_member(org_id, user_id, current_user)


@router.get("/{org_id}/stats", response_model=OrgStatsResponse)
async def get_org_stats(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrgStatsResponse:
    service = OrganizationService(db)
    # Verify membership
    await service.get_organization(org_id, current_user)

    total_scans = (await db.execute(
        select(func.count()).select_from(Scan).where(Scan.org_id == org_id)
    )).scalar_one()

    active_scans = (await db.execute(
        select(func.count()).select_from(Scan).where(
            Scan.org_id == org_id,
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
        )
    )).scalar_one()

    open_critical = (await db.execute(
        select(func.count())
        .select_from(ScanFinding)
        .join(Scan, ScanFinding.scan_id == Scan.id)
        .where(
            Scan.org_id == org_id,
            ScanFinding.risk_level == RiskLevel.CRITICAL,
            ScanFinding.status == FindingStatus.OPEN,
        )
    )).scalar_one()

    open_high = (await db.execute(
        select(func.count())
        .select_from(ScanFinding)
        .join(Scan, ScanFinding.scan_id == Scan.id)
        .where(
            Scan.org_id == org_id,
            ScanFinding.risk_level == RiskLevel.HIGH,
            ScanFinding.status == FindingStatus.OPEN,
        )
    )).scalar_one()

    latest_scan = (await db.execute(
        select(Scan)
        .where(
            Scan.org_id == org_id,
            Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.PARTIAL]),
        )
        .order_by(Scan.completed_at.desc())
        .limit(1)
    )).scalar_one_or_none()

    return OrgStatsResponse(
        total_scans=total_scans,
        active_scans=active_scans,
        open_critical=open_critical,
        open_high=open_high,
        latest_scan_id=str(latest_scan.id) if latest_scan else None,
        latest_risk_score=latest_scan.risk_score if latest_scan else None,
        latest_risk_posture=_risk_posture(latest_scan.risk_score)
        if latest_scan and latest_scan.risk_score is not None
        else None,
    )


@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: uuid.UUID,
    body: UpdateOrgRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrganizationResponse:
    service = OrganizationService(db)
    org = await service.update_organization(org_id, body.name, current_user)
    return await _org_response(db, org, current_user)


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    service = OrganizationService(db)
    await service.soft_delete_organization(org_id, current_user)


# Audit entries carry member IPs and admin actions: org admins only
@router.get("/{org_id}/audit", response_model=AuditLogListResponse,
            dependencies=[Depends(RequirePermission("org:manage_members"))])
async def list_audit_logs(
    org_id: uuid.UUID,
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    user_id: Optional[uuid.UUID] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditLogListResponse:
    service = OrganizationService(db)
    # Require org membership
    await service.get_organization(org_id, current_user)

    filters = [AuditLog.org_id == org_id]
    if action:
        filters.append(AuditLog.action == action)
    if resource_type:
        filters.append(AuditLog.resource_type == resource_type)
    if user_id:
        filters.append(AuditLog.user_id == user_id)

    total = (await db.execute(
        select(func.count()).select_from(AuditLog).where(*filters)
    )).scalar_one()

    offset = (page - 1) * page_size
    rows = (await db.execute(
        select(AuditLog).where(*filters)
        .order_by(AuditLog.created_at.desc())
        .offset(offset).limit(page_size)
    )).scalars().all()

    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{org_id}/pentest-config")
async def get_pentest_config(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    service = OrganizationService(db)
    org = await service.get_organization(org_id, current_user)
    cfg = org.pentest_config or {}
    view = _pentest_config_view(cfg)
    # The canary address is an org secret-ish setting: only roles that can edit
    # the config (org:write) read it; others only learn whether one is set.
    roles = await _member_roles(db, current_user, [org.id])
    can_write = _role_has(_role_for(roles, org.id, current_user), "org:write")
    view["canary_email_configured"] = view["canary_email"] is not None
    if not can_write:
        view["canary_email"] = None
    return view


_CANARY_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_CANARY_TEST_PER_MINUTE = 3


class PentestConfigUpdate(BaseModel):
    """PATCH /orgs/{id}/pentest-config body. Unknown keys are rejected (no JSONB injection)."""

    model_config = ConfigDict(extra="forbid")

    cred_probe_enabled: Optional[StrictBool] = None
    web_active_probe_enabled: Optional[StrictBool] = None
    canary_email: Optional[str] = Field(default=None, max_length=254)

    @field_validator("canary_email")
    @classmethod
    def _check_canary_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if v == "":
            return ""
        if not _CANARY_EMAIL_RE.match(v):
            raise ValueError("Invalid canary_email format")
        return v


def _pentest_config_view(cfg: dict) -> dict:
    return {
        "cred_probe_enabled": bool(cfg.get("cred_probe_enabled", False)),
        "web_active_probe_enabled": bool(cfg.get("web_active_probe_enabled", False)),
        "canary_email": cfg.get("canary_email") or None,
    }


@router.post(
    "/{org_id}/pentest-config/test-canary",
    dependencies=[Depends(RequirePermission("org:write"))],
)
async def test_canary_email(
    org_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    from app.services.email_service import send_email
    from app.core.config import settings as app_settings

    service = OrganizationService(db)
    org = await service.get_organization(org_id, current_user)
    # Sends real mail: throttled per (org, client IP) so it cannot be used as a mail cannon
    await check_rate_limit(
        request,
        route_category=f"canary_test:{org.id}",
        limit=_CANARY_TEST_PER_MINUTE,
        window_seconds=60,
    )
    cfg = org.pentest_config or {}
    canary_email = cfg.get("canary_email")

    if not canary_email:
        raise HTTPException(status_code=400, detail="Canary email not configured")

    if not app_settings.SMTP_HOST:
        return {"sent": False, "reason": "no_smtp_config"}

    text = (
        "This is a test message from MAILOX to verify your canary address is working.\n\n"
        "If you received this, your canary email is correctly configured.\n\n"
        "— MAILOX Security Assessment Platform"
    )
    html = """
<html><body style="font-family:sans-serif;color:#222;max-width:480px;margin:0 auto;padding:24px">
  <h2 style="color:#111">Canary address verified</h2>
  <p>This is a test message from <strong>MAILOX</strong> to confirm your canary address is working correctly.</p>
  <p>If you received this email, your canary probes will deliver results to this address during scans.</p>
  <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
  <p style="color:#999;font-size:12px">MAILOX — Email Security Assessment Platform</p>
</body></html>
"""
    await send_email(
        to=canary_email,
        subject="[MAILOX] Canary address test",
        html=html,
        text=text,
    )
    return {"sent": True}


@router.patch(
    "/{org_id}/pentest-config",
    dependencies=[Depends(RequirePermission("org:write"))],
)
async def update_pentest_config(
    org_id: uuid.UUID,
    body: PentestConfigUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    service = OrganizationService(db)
    org = await service.get_organization(org_id, current_user)

    before = _pentest_config_view(dict(org.pentest_config or {}))
    cfg = dict(org.pentest_config or {})
    sent = body.model_dump(exclude_unset=True)
    if sent.get("cred_probe_enabled") is not None:
        cfg["cred_probe_enabled"] = sent["cred_probe_enabled"]
    if sent.get("web_active_probe_enabled") is not None:
        cfg["web_active_probe_enabled"] = sent["web_active_probe_enabled"]
    if "canary_email" in sent:
        cfg["canary_email"] = sent["canary_email"] or None

    await db.execute(
        update(Organization)
        .where(Organization.id == org.id)
        .values(pentest_config=cfg)
    )
    after = _pentest_config_view(cfg)
    db.add(AuditLog(
        id=uuid.uuid4(),
        org_id=org.id,
        user_id=current_user.id,
        action="org.pentest_config.update",
        resource_type="organization",
        resource_id=str(org.id),
        details={
            "changes": {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]},
        },
        ip_address=_extract_client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512],
        created_at=datetime.now(timezone.utc),
    ))
    await db.commit()

    return after


def _risk_posture(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "clean"
