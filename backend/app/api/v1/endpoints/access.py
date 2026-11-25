"""Edition info, SaaS access requests, invites, account administration, domain proof."""
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org, rate_limit_auth
from app.core.config import settings
from app.core.rate_limiter import _extract_client_ip
from app.db.models.audit import AuditLog
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.access import (
    AccessRequestCreate,
    AccessRequestOut,
    AdminFlag,
    AdminOrgOut,
    AdminOrgUpdate,
    AdminUserDetail,
    AdminUserOut,
    EditionInfo,
    InviteCreate,
    InviteIssued,
    InviteLookup,
    InviteOut,
    VerifiedDomainCreate,
    VerifiedDomainOut,
    VerifyResult,
)
from app.services.access_service import AccessService, registration_mode
from app.services.admin_service import AdminService
from app.services.domain_verification import DomainVerificationService

async def require_saas() -> None:
    """SaaS-only routes answer 404 on a self-hosted instance, as if not mounted.

    Evaluated per request (not at mount time) so the edition is read from the live
    settings. Clients learn the edition from GET /meta.
    """
    if not settings.IS_SAAS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


public_router = APIRouter(tags=["edition"])
admin_router = APIRouter(prefix="/admin", tags=["admin"])
# Domain ownership proof only exists on SaaS
domains_router = APIRouter(prefix="/domains", tags=["domains"], dependencies=[Depends(require_saas)])


async def require_platform_admin(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_platform_admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return current_user


async def _audit(db: AsyncSession, action: str, user: Optional[User], request: Request,
                 resource_type: str, resource_id: Optional[uuid.UUID], details: Optional[dict] = None,
                 org_id: Optional[uuid.UUID] = None) -> None:
    db.add(AuditLog(
        org_id=org_id, user_id=user.id if user else None, action=action,
        resource_type=resource_type, resource_id=str(resource_id) if resource_id else None,
        details=details or {}, ip_address=_extract_client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512],
        created_at=datetime.now(timezone.utc),
    ))


def _issued(invite) -> InviteIssued:
    sent = bool(getattr(invite, "email_sent", False))
    out = InviteIssued(**InviteOut.model_validate(invite).model_dump(), email_sent=sent)
    if not sent:
        out.invite_url = f"{settings.FRONTEND_URL}/register?invite={invite.plain_token}"
    return out


# ── Public ───────────────────────────────────────────────────────────────────

@public_router.get("/meta", response_model=EditionInfo)
async def edition_info(db: AsyncSession = Depends(get_db)) -> EditionInfo:
    return EditionInfo(
        edition=settings.MAILOX_EDITION,
        # "local" tells the frontend to try one-click /auth/local-session, which only
        # answers when explicitly enabled on a non-SaaS instance
        auth="local" if settings.LOCAL_SESSION_ENABLED and not settings.IS_SAAS else "accounts",
        registration=await registration_mode(db),
        domain_verification_required=settings.IS_SAAS,
        verify_prefix=settings.DOMAIN_VERIFY_PREFIX,
    )


@public_router.post("/access-requests", status_code=status.HTTP_202_ACCEPTED,
                    dependencies=[Depends(rate_limit_auth)])
async def create_access_request(
    body: AccessRequestCreate, request: Request, db: AsyncSession = Depends(get_db),
) -> dict:
    """Receives the marketing site's form. Same 202 answer whatever happens, so the
    endpoint reveals nothing about existing requests or accounts."""
    if not settings.IS_SAAS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if body.website:
        return {"status": "received"}  # honeypot filled: drop silently
    req = await AccessService(db).submit_request(
        email=body.email, name=body.name, company=body.company, role=body.role,
        message=body.message, topic=body.topic, ip=_extract_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    await _audit(db, "access.request", None, request, "access_request", req.id, {"topic": body.topic})
    return {"status": "received"}


@public_router.get("/invites/{token}", response_model=InviteLookup,
                   dependencies=[Depends(rate_limit_auth)])
async def lookup_invite(token: str, db: AsyncSession = Depends(get_db)) -> InviteLookup:
    email = await AccessService(db).describe_invite(token)
    return InviteLookup(email=email, valid=email is not None)


# ── Platform admin ───────────────────────────────────────────────────────────

@admin_router.get("/access-requests", response_model=list[AccessRequestOut],
                  dependencies=[Depends(require_saas)])
async def list_access_requests(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    _: User = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
) -> list[AccessRequestOut]:
    return [AccessRequestOut.model_validate(r) for r in await AccessService(db).list_requests(status_filter)]


@admin_router.post("/access-requests/{request_id}/approve", response_model=InviteIssued,
                   dependencies=[Depends(require_saas)])
async def approve_access_request(
    request_id: uuid.UUID, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> InviteIssued:
    invite = await AccessService(db).approve_request(request_id, admin)
    await _audit(db, "access.approve", admin, request, "access_request", request_id, {"email": invite.email})
    return _issued(invite)


@admin_router.post("/access-requests/{request_id}/reject", response_model=AccessRequestOut,
                   dependencies=[Depends(require_saas)])
async def reject_access_request(
    request_id: uuid.UUID, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> AccessRequestOut:
    req = await AccessService(db).reject_request(request_id, admin)
    await _audit(db, "access.reject", admin, request, "access_request", request_id, {"email": req.email})
    return AccessRequestOut.model_validate(req)


@admin_router.get("/invites", response_model=list[InviteOut])
async def list_invites(_: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db)) -> list[InviteOut]:
    return [InviteOut.model_validate(i) for i in await AccessService(db).list_invites()]


@admin_router.post("/invites", response_model=InviteIssued, status_code=status.HTTP_201_CREATED)
async def create_invite(
    body: InviteCreate, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> InviteIssued:
    invite = await AccessService(db).issue_invite(body.email, body.name or body.email, admin)
    await _audit(db, "access.invite", admin, request, "access_invite", invite.id, {"email": invite.email})
    return _issued(invite)


@admin_router.post("/invites/{invite_id}/revoke", response_model=InviteOut)
async def revoke_invite(
    invite_id: uuid.UUID, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> InviteOut:
    invite = await AccessService(db).revoke_invite(invite_id)
    await _audit(db, "access.invite_revoke", admin, request, "access_invite", invite_id)
    return InviteOut.model_validate(invite)


@admin_router.get("/users", response_model=list[AdminUserDetail])
async def list_users(_: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db)) -> list[AdminUserDetail]:
    return [AdminUserDetail(**u) for u in await AdminService(db).list_users()]


@admin_router.post("/users/{user_id}/suspend", response_model=AdminUserOut)
async def suspend_user(
    user_id: uuid.UUID, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> AdminUserOut:
    user = await AccessService(db).set_user_active(user_id, False, admin)
    await _audit(db, "admin.user_suspend", admin, request, "user", user_id)
    return AdminUserOut.model_validate(user)


@admin_router.post("/users/{user_id}/activate", response_model=AdminUserOut)
async def activate_user(
    user_id: uuid.UUID, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> AdminUserOut:
    user = await AccessService(db).set_user_active(user_id, True, admin)
    await _audit(db, "admin.user_activate", admin, request, "user", user_id)
    return AdminUserOut.model_validate(user)


# ── Domain ownership (per org) ───────────────────────────────────────────────

def _domain_out(record) -> VerifiedDomainOut:
    out = VerifiedDomainOut.model_validate(record)
    out.txt_name = record.domain
    out.txt_value = settings.DOMAIN_VERIFY_PREFIX + record.token
    return out


@domains_router.get("", response_model=list[VerifiedDomainOut],
                    dependencies=[Depends(RequirePermission("assessment:read"))])
async def list_domains(
    org_id: uuid.UUID = Depends(get_verified_org), db: AsyncSession = Depends(get_db),
) -> list[VerifiedDomainOut]:
    return [_domain_out(r) for r in await DomainVerificationService(db).list_domains(org_id)]


@domains_router.post("", response_model=VerifiedDomainOut, status_code=status.HTTP_201_CREATED,
                     dependencies=[Depends(RequirePermission("assessment:write"))])
async def add_domain(
    body: VerifiedDomainCreate, request: Request,
    org_id: uuid.UUID = Depends(get_verified_org),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
) -> VerifiedDomainOut:
    record = await DomainVerificationService(db).add(org_id, body.domain, current_user.id)
    await _audit(db, "domain.add", current_user, request, "verified_domain", record.id,
                 {"domain": record.domain}, org_id=org_id)
    return _domain_out(record)


@domains_router.post("/{domain_id}/verify", response_model=VerifyResult,
                     dependencies=[Depends(RequirePermission("assessment:write"))])
async def verify_domain(
    domain_id: uuid.UUID, request: Request,
    org_id: uuid.UUID = Depends(get_verified_org),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
) -> VerifyResult:
    record, values = await DomainVerificationService(db).verify(org_id, domain_id)
    if record.verified_at:
        await _audit(db, "domain.verify", current_user, request, "verified_domain", record.id,
                     {"domain": record.domain}, org_id=org_id)
    return VerifyResult(domain=_domain_out(record), verified=record.verified_at is not None, txt_found=values[:20])


@domains_router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT,
                       dependencies=[Depends(RequirePermission("assessment:write"))])
async def delete_domain(
    domain_id: uuid.UUID, request: Request,
    org_id: uuid.UUID = Depends(get_verified_org),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
) -> Response:
    await DomainVerificationService(db).remove(org_id, domain_id)
    await _audit(db, "domain.remove", current_user, request, "verified_domain", domain_id, org_id=org_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@admin_router.post("/users/{user_id}/platform-admin", response_model=AdminUserOut)
async def set_platform_admin(
    user_id: uuid.UUID, body: AdminFlag, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> AdminUserOut:
    user = await AdminService(db).set_platform_admin(user_id, body.enabled, admin)
    await _audit(db, "admin.platform_admin", admin, request, "user", user_id, {"enabled": body.enabled})
    return AdminUserOut.model_validate(user)


@admin_router.post("/users/{user_id}/revoke-sessions", response_model=AdminUserOut)
async def revoke_user_sessions(
    user_id: uuid.UUID, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> AdminUserOut:
    user = await AdminService(db).revoke_sessions(user_id)
    await _audit(db, "admin.revoke_sessions", admin, request, "user", user_id)
    return AdminUserOut.model_validate(user)


@admin_router.post("/users/{user_id}/reset-mfa", response_model=AdminUserOut)
async def reset_user_mfa(
    user_id: uuid.UUID, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> AdminUserOut:
    user = await AdminService(db).reset_mfa(user_id)
    await _audit(db, "admin.reset_mfa", admin, request, "user", user_id)
    return AdminUserOut.model_validate(user)


@admin_router.get("/orgs", response_model=list[AdminOrgOut])
async def list_orgs(_: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db)) -> list[AdminOrgOut]:
    return [AdminOrgOut(**o) for o in await AdminService(db).list_orgs()]


@admin_router.get("/email-logs")
async def list_email_logs(
    _: User = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict]:
    """List recent email logs for admin review."""
    from app.db.models.email_log import EmailLog
    from app.schemas.access import EmailLogOut
    result = await db.execute(
        select(EmailLog).order_by(EmailLog.created_at.desc()).limit(limit)
    )
    logs = result.scalars().all()
    return [EmailLogOut.model_validate(log).model_dump() for log in logs]


@admin_router.patch("/orgs/{org_id}", response_model=AdminOrgOut)
async def update_org(
    org_id: uuid.UUID, body: AdminOrgUpdate, request: Request,
    admin: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db),
) -> AdminOrgOut:
    changes = body.model_dump(include=body.model_fields_set)
    if changes.get("offensive_modules_allowed") is None:
        changes.pop("offensive_modules_allowed", None)
    if changes.get("is_active") is None:
        changes.pop("is_active", None)
    row = await AdminService(db).update_org(org_id, changes)
    await _audit(db, "admin.org_update", admin, request, "organization", org_id,
                 {k: v for k, v in changes.items()}, org_id=org_id)
    return AdminOrgOut(**row)
