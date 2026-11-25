"""Who may create an account.

Registration is always invite-only after the first admin account is created.
The first admin is created via CLI: `python -m app.cli create-admin`.

Flow:
1. Access request submitted from landing page
2. Admin approves request in /admin/access
3. Invite email sent with one-time token
4. User registers via /register?invite=<token>
"""
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.db.models.access import AccessInvite, AccessRequest, AccessRequestStatus
from app.db.models.auth_tokens import RefreshToken
from app.db.models.user import User
from app.services import email_service

logger = get_logger("mailox.access")

# Serialises "is this the first account?" so two concurrent signups on a fresh
# self-hosted install cannot both become platform admin.
_FIRST_USER_LOCK = 0x4D41494C  # "MAIL"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RegistrationMode:
    FIRST_USER = "first_user"   # selfhosted, no account yet: the next one becomes admin
    OPEN = "open"               # deprecated, kept for compatibility
    INVITE = "invite"           # an invite is required (always after first user)


async def registration_mode(db: AsyncSession) -> str:
    """Registration is always invite-only after the first admin account is created.

    Access requests come from the landing page, admin approves them, and an
    invite email is sent with a one-time token.
    """
    # SaaS: the first platform admin is created only via `python -m app.cli
    # create-admin`. A public /auth/register on an empty database must never
    # hand out platform admin.
    if settings.IS_SAAS:
        return RegistrationMode.INVITE
    has_users = (await db.execute(select(func.count()).select_from(User))).scalar_one() > 0
    if not has_users:
        return RegistrationMode.FIRST_USER
    return RegistrationMode.INVITE


class AccessService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ── Signup gate ──────────────────────────────────────────────────────────

    async def authorize_registration(
        self, email: str, invite_token: Optional[str], bootstrap_allowed: bool = False,
    ) -> tuple[bool, Optional[AccessInvite]]:
        """Decide whether this signup may proceed.

        Returns (make_platform_admin, invite_to_consume). Raises 403 otherwise.
        `bootstrap_allowed`: the request comes from the host itself, the only place
        allowed to claim the first (platform admin) account of an empty instance.
        """
        await self.db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _FIRST_USER_LOCK})
        mode = await registration_mode(self.db)
        if mode == RegistrationMode.FIRST_USER:
            if not bootstrap_allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "The first account of this instance becomes its administrator and can "
                        "only be created from the host itself: open MAILOX on the server "
                        "(http://localhost) to register, or run "
                        "`python -m app.cli create-admin` on the server."
                    ),
                )
            return True, None
        if mode == RegistrationMode.OPEN and not invite_token:
            return False, None
        if not invite_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Registration requires an invitation. Request access first.",
            )
        invite = await self._usable_invite(invite_token)
        if invite is None or invite.email.lower() != email.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This invitation is invalid, expired, already used, or for another email.",
            )
        return False, invite

    async def consume_invite(self, invite: AccessInvite) -> None:
        invite.used_at = _now()

    async def _usable_invite(self, token: str) -> Optional[AccessInvite]:
        result = await self.db.execute(
            select(AccessInvite).where(AccessInvite.token_hash == _hash_token(token)).with_for_update()
        )
        invite = result.scalar_one_or_none()
        if invite is None or invite.used_at or invite.revoked_at or invite.expires_at <= _now():
            return None
        return invite

    async def describe_invite(self, token: str) -> Optional[str]:
        """Email an unused invite is for, so the signup form can prefill it."""
        result = await self.db.execute(
            select(AccessInvite).where(AccessInvite.token_hash == _hash_token(token))
        )
        invite = result.scalar_one_or_none()
        if invite is None or invite.used_at or invite.revoked_at or invite.expires_at <= _now():
            return None
        return invite.email

    # ── Access requests (saas) ───────────────────────────────────────────────

    async def submit_request(
        self, *, email: str, name: str, company: str, role: Optional[str],
        message: Optional[str], topic: str, ip: Optional[str], user_agent: Optional[str],
    ) -> AccessRequest:
        email = email.lower().strip()
        existing = (await self.db.execute(
            select(AccessRequest).where(
                AccessRequest.email == email,
                AccessRequest.status == AccessRequestStatus.PENDING.value,
                AccessRequest.topic == topic,
            )
        )).scalar_one_or_none()
        if existing:
            return existing  # do not stack duplicates or re-notify

        req = AccessRequest(
            email=email, name=name.strip(), company=company.strip(),
            role=(role or "").strip() or None, message=(message or "").strip() or None,
            topic=topic, ip_address=ip, user_agent=(user_agent or "")[:512] or None,
        )
        self.db.add(req)
        await self.db.flush()

        if settings.ADMIN_NOTIFY_EMAIL:
            try:
                await email_service.send_access_request_notification(
                    settings.ADMIN_NOTIFY_EMAIL, str(req.id), req.name, req.email,
                    req.company, req.role, req.message,
                )
            except Exception as exc:  # the request is stored; notification is best effort
                logger.error("access_request.notify_failed", error=str(exc))
        return req

    async def list_requests(self, status_filter: Optional[str]) -> list[AccessRequest]:
        q = select(AccessRequest).order_by(AccessRequest.created_at.desc()).limit(500)
        if status_filter:
            q = q.where(AccessRequest.status == status_filter)
        return list((await self.db.execute(q)).scalars())

    async def _get_request(self, request_id: uuid.UUID) -> AccessRequest:
        req = await self.db.get(AccessRequest, request_id, with_for_update=True)
        if req is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return req

    async def approve_request(self, request_id: uuid.UUID, admin: User) -> AccessInvite:
        req = await self._get_request(request_id)
        if req.status != AccessRequestStatus.PENDING.value:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Request already {req.status}")
        if req.topic != "access":
            # Demo and general questions come through the same form; they are answered, not approved
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only access requests can be approved")
        req.status = AccessRequestStatus.APPROVED.value
        req.reviewed_at = _now()
        req.reviewed_by = admin.id
        return await self.issue_invite(req.email, req.name, admin, request_id=req.id)

    async def reject_request(self, request_id: uuid.UUID, admin: User) -> AccessRequest:
        req = await self._get_request(request_id)
        if req.status != AccessRequestStatus.PENDING.value:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Request already {req.status}")
        req.status = AccessRequestStatus.REJECTED.value
        req.reviewed_at = _now()
        req.reviewed_by = admin.id
        return req

    # ── Invites ──────────────────────────────────────────────────────────────

    async def issue_invite(
        self, email: str, name: str, admin: Optional[User], request_id: Optional[uuid.UUID] = None,
        send: bool = True,
    ) -> AccessInvite:
        """Create an invite and email the link. Older unused invites for the email are revoked."""
        email = email.lower().strip()
        existing_user = (await self.db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account already exists for this email")

        await self.db.execute(
            update(AccessInvite)
            .where(AccessInvite.email == email, AccessInvite.used_at.is_(None), AccessInvite.revoked_at.is_(None))
            .values(revoked_at=_now())
        )
        token = secrets.token_urlsafe(32)
        invite = AccessInvite(
            request_id=request_id, email=email, token_hash=_hash_token(token),
            expires_at=_now() + timedelta(hours=settings.ACCESS_INVITE_TTL_HOURS),
            created_by=admin.id if admin else None,
        )
        self.db.add(invite)
        await self.db.flush()
        invite.plain_token = token  # type: ignore[attr-defined]  # returned once, never stored
        invite.email_sent = False  # type: ignore[attr-defined]
        if send and settings.SMTP_HOST:
            try:
                await email_service.send_access_invite_email(email, name, token, settings.ACCESS_INVITE_TTL_HOURS)
                invite.email_sent = True  # type: ignore[attr-defined]
            except Exception as exc:
                # Keep the invite: the admin gets the link back and can pass it on
                logger.error("access_invite.email_failed", email=email, error=str(exc))
        return invite

    async def list_invites(self) -> list[AccessInvite]:
        q = select(AccessInvite).order_by(AccessInvite.created_at.desc()).limit(500)
        return list((await self.db.execute(q)).scalars())

    async def revoke_invite(self, invite_id: uuid.UUID) -> AccessInvite:
        invite = await self.db.get(AccessInvite, invite_id, with_for_update=True)
        if invite is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        if invite.used_at is None and invite.revoked_at is None:
            invite.revoked_at = _now()
        return invite

    # ── Accounts ─────────────────────────────────────────────────────────────

    async def set_user_active(self, user_id: uuid.UUID, active: bool, admin: User) -> User:
        user = await self.db.get(User, user_id, with_for_update=True)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        if user.id == admin.id and not active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot suspend your own account")
        user.is_active = active
        if not active:
            # Access tokens are short-lived; dropping refresh tokens ends the session soon after
            await self.db.execute(
                update(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
                .values(revoked_at=_now())
            )
        return user
