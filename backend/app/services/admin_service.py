"""Platform administration: accounts and organizations, never their assessment data.

Everything here is account metadata (who, which org, role, limits, usage counts).
Scan targets, findings and domains stay private to each organization in the SaaS edition.
"""
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.access import VerifiedDomain
from app.db.models.auth_tokens import RefreshToken
from app.db.models.organization import Organization, OrganizationMember
from app.db.models.scan import Scan
from app.db.models.user import User
from app.services.scan_service import SCANS_PER_ORG_PER_DAY


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AdminService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ── Accounts ─────────────────────────────────────────────────────────────

    async def list_users(self) -> list[dict]:
        users = list((await self.db.execute(select(User).order_by(User.created_at.desc()).limit(1000))).scalars())
        rows = (await self.db.execute(
            select(OrganizationMember.user_id, Organization.id, Organization.name, OrganizationMember.role)
            .join(Organization, Organization.id == OrganizationMember.org_id)
            .where(OrganizationMember.is_active == True)  # noqa: E712
        )).all()
        orgs_by_user: dict[uuid.UUID, list[dict]] = defaultdict(list)
        for user_id, org_id, org_name, role in rows:
            orgs_by_user[user_id].append({"id": org_id, "name": org_name, "role": getattr(role, "value", role)})
        return [
            {
                "id": u.id, "email": u.email, "full_name": u.full_name, "is_active": u.is_active,
                "is_platform_admin": u.is_platform_admin, "mfa_enabled": u.mfa_enabled,
                "locked_until": u.locked_until, "created_at": u.created_at, "orgs": orgs_by_user.get(u.id, []),
            }
            for u in users
        ]

    async def _user(self, user_id: uuid.UUID) -> User:
        user = await self.db.get(User, user_id, with_for_update=True)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return user

    async def revoke_sessions(self, user_id: uuid.UUID) -> User:
        user = await self._user(user_id)
        await self.db.execute(
            update(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=_now())
        )
        return user

    async def set_platform_admin(self, user_id: uuid.UUID, enabled: bool, admin: User) -> User:
        user = await self._user(user_id)
        if user.id == admin.id and not enabled:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot remove your own admin rights")
        user.is_platform_admin = enabled
        return user

    async def reset_mfa(self, user_id: uuid.UUID) -> User:
        """For a user who lost their authenticator. They log in with the password alone, then re-enrol."""
        user = await self._user(user_id)
        user.mfa_enabled = False
        user.mfa_secret_encrypted = None
        user.mfa_backup_codes_encrypted = None
        user.mfa_last_used_totp = None
        user.failed_login_attempts = 0
        user.locked_until = None
        await self.revoke_sessions(user_id)
        return user

    # ── Organizations ────────────────────────────────────────────────────────

    async def list_orgs(self) -> list[dict]:
        orgs = list((await self.db.execute(select(Organization).order_by(Organization.created_at.desc()).limit(1000))).scalars())
        now = _now()
        scans_24h = dict((await self.db.execute(
            select(Scan.org_id, func.count(Scan.id)).where(Scan.created_at >= now - timedelta(hours=24)).group_by(Scan.org_id)
        )).all())
        scans_30d = dict((await self.db.execute(
            select(Scan.org_id, func.count(Scan.id)).where(Scan.created_at >= now - timedelta(days=30)).group_by(Scan.org_id)
        )).all())
        domains = dict((await self.db.execute(
            select(VerifiedDomain.org_id, func.count(VerifiedDomain.id))
            .where(VerifiedDomain.verified_at.is_not(None)).group_by(VerifiedDomain.org_id)
        )).all())
        members = (await self.db.execute(
            select(OrganizationMember.org_id, User.email, OrganizationMember.role)
            .join(User, User.id == OrganizationMember.user_id)
            .where(OrganizationMember.is_active == True)  # noqa: E712
        )).all()
        members_by_org: dict[uuid.UUID, list[dict]] = defaultdict(list)
        for org_id, email, role in members:
            members_by_org[org_id].append({"email": email, "role": getattr(role, "value", role)})
        return [self._org_row(o, members_by_org, scans_24h, scans_30d, domains) for o in orgs]

    @staticmethod
    def _org_row(o: Organization, members, scans_24h, scans_30d, domains) -> dict:
        return {
            "id": o.id, "name": o.name, "slug": o.slug, "is_active": o.is_active, "created_at": o.created_at,
            "daily_scan_quota": o.daily_scan_quota,
            "effective_daily_scan_quota": o.daily_scan_quota if o.daily_scan_quota is not None else SCANS_PER_ORG_PER_DAY,
            "offensive_modules_allowed": o.offensive_modules_allowed,
            "members": members.get(o.id, []),
            "scans_24h": scans_24h.get(o.id, 0), "scans_30d": scans_30d.get(o.id, 0),
            "verified_domains": domains.get(o.id, 0),
        }

    async def update_org(self, org_id: uuid.UUID, changes: dict) -> dict:
        org = await self.db.get(Organization, org_id, with_for_update=True)
        if org is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        for field in ("daily_scan_quota", "offensive_modules_allowed", "is_active"):
            if field in changes:
                setattr(org, field, changes[field])
        await self.db.flush()
        rows = await self.list_orgs()
        return next(r for r in rows if r["id"] == org_id)

    async def org_name(self, org_id: uuid.UUID) -> Optional[str]:
        org = await self.db.get(Organization, org_id)
        return org.name if org else None
