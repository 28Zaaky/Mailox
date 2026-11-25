import re
import uuid
from typing import List, Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.audit import AuditLog
from app.db.models.organization import OrgRole, Organization, OrganizationMember
from app.db.models.user import User

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,98}[a-z0-9]$")


class OrganizationService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create_organization(
        self, name: str, slug: str, creator: User
    ) -> Organization:
        # SaaS: the daily scan quota is per organization, so one account must not be
        # able to multiply it by creating organizations. Platform admins are exempt.
        if settings.IS_SAAS and not creator.is_platform_admin:
            owned = (await self.db.execute(
                select(func.count()).select_from(OrganizationMember).where(
                    OrganizationMember.user_id == creator.id,
                    OrganizationMember.role == OrgRole.ORG_ADMIN,
                    OrganizationMember.is_active == True,  # noqa: E712
                )
            )).scalar_one()
            if owned >= settings.SAAS_MAX_ORGS_PER_USER:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"An account can own at most {settings.SAAS_MAX_ORGS_PER_USER} organization(s) on this service.",
                )

        # Slug uniqueness check
        result = await self.db.execute(
            select(Organization).where(Organization.slug == slug)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Slug already taken",
            )

        # SaaS: offensive modules (active/canary/credential probes, active web
        # injection) stay off until a platform admin explicitly enables them for
        # the organization. Self-hosted: the operator owns the tool, keep them on.
        default_pentest_cfg = (
            {"cred_probe_enabled": True, "web_active_probe_enabled": True}
            if not settings.IS_SAAS
            else {}
        )
        org = Organization(
            name=name.strip(), slug=slug,
            offensive_modules_allowed=not settings.IS_SAAS,
            pentest_config=default_pentest_cfg,
        )
        self.db.add(org)
        await self.db.flush()

        # Creator becomes ORG_ADMIN automatically
        membership = OrganizationMember(
            org_id=org.id,
            user_id=creator.id,
            role=OrgRole.ORG_ADMIN,
        )
        self.db.add(membership)
        await self.db.flush()

        return org

    async def get_organization(
        self, org_id: uuid.UUID, requesting_user: User
    ) -> Organization:
        """Returns org only if user is a member (or platform admin)."""
        org = await self._load_org_or_404(org_id)
        if not requesting_user.sees_all_orgs:
            await self._require_membership(org_id, requesting_user.id)
        return org

    async def list_user_organizations(self, user: User) -> List[Organization]:
        """Return organizations where the user is an active member.

        Even platform admins see only their own orgs here — the org switcher
        should not expose other customers' data. The admin panel uses
        /admin/orgs for the full list.
        """
        result = await self.db.execute(
            select(Organization)
            .join(OrganizationMember, OrganizationMember.org_id == Organization.id)
            .where(
                OrganizationMember.user_id == user.id,
                OrganizationMember.is_active == True,
                Organization.is_active == True,
            )
        )
        return list(result.scalars().all())

    async def add_member(
        self,
        org_id: uuid.UUID,
        email: str,
        role: str,
        requesting_user: User,
    ) -> tuple[OrganizationMember, User]:
        await self._require_permission(org_id, requesting_user, "org:manage_members")

        user_result = await self.db.execute(
            select(User).where(User.email == email.lower())
        )
        target_user = user_result.scalar_one_or_none()
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Check existing membership
        existing = await self.db.execute(
            select(OrganizationMember).where(
                OrganizationMember.org_id == org_id,
                OrganizationMember.user_id == target_user.id,
            )
        )
        existing_member = existing.scalar_one_or_none()
        if existing_member:
            if existing_member.is_active:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User is already a member",
                )
            # Re-activate with new role
            existing_member.is_active = True
            existing_member.role = OrgRole(role)
            await self.db.flush()
            return existing_member, target_user

        membership = OrganizationMember(
            org_id=org_id,
            user_id=target_user.id,
            role=OrgRole(role),
        )
        self.db.add(membership)
        await self.db.flush()
        return membership, target_user

    async def list_members(
        self, org_id: uuid.UUID, requesting_user: User
    ) -> List[tuple[OrganizationMember, User]]:
        await self._require_membership(org_id, requesting_user.id)
        result = await self.db.execute(
            select(OrganizationMember, User)
            .join(User, OrganizationMember.user_id == User.id)
            .where(
                OrganizationMember.org_id == org_id,
                OrganizationMember.is_active == True,
            )
        )
        return list(result.all())

    async def remove_member(
        self,
        org_id: uuid.UUID,
        user_id: uuid.UUID,
        requesting_user: User,
    ) -> None:
        await self._require_permission(org_id, requesting_user, "org:manage_members")

        result = await self.db.execute(
            select(OrganizationMember).where(
                OrganizationMember.org_id == org_id,
                OrganizationMember.user_id == user_id,
                OrganizationMember.is_active == True,
            )
        )
        membership = result.scalar_one_or_none()
        if not membership:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

        if user_id == requesting_user.id:
            # Count remaining admins to prevent removing last admin
            admin_count = (await self.db.execute(
                select(func.count()).where(
                    OrganizationMember.org_id == org_id,
                    OrganizationMember.role == OrgRole.ORG_ADMIN,
                    OrganizationMember.is_active == True,
                )
            )).scalar_one()
            if admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot remove the last organization admin",
                )

        membership.is_active = False
        await self.db.flush()

    async def _load_org_or_404(self, org_id: uuid.UUID) -> Organization:
        result = await self.db.execute(
            select(Organization).where(Organization.id == org_id, Organization.is_active == True)
        )
        org = result.scalar_one_or_none()
        if not org:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return org

    async def _require_membership(
        self, org_id: uuid.UUID, user_id: uuid.UUID
    ) -> OrganizationMember:
        result = await self.db.execute(
            select(OrganizationMember).where(
                OrganizationMember.org_id == org_id,
                OrganizationMember.user_id == user_id,
                OrganizationMember.is_active == True,
            )
        )
        membership = result.scalar_one_or_none()
        if not membership:
            # Return 404, not 403 — prevents IDOR oracle
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return membership

    async def update_organization(
        self, org_id: uuid.UUID, name: str, requesting_user: User
    ) -> Organization:
        await self._require_permission(org_id, requesting_user, "org:write")
        org = await self._load_org_or_404(org_id)
        org.name = name.strip()
        await self.db.flush()
        await self.db.refresh(org)
        return org

    async def soft_delete_organization(
        self, org_id: uuid.UUID, requesting_user: User
    ) -> None:
        await self._require_permission(org_id, requesting_user, "org:manage_members")
        org = await self._load_org_or_404(org_id)
        # Prevent deletion of last admin's only org — safety check
        admin_count = (await self.db.execute(
            select(func.count()).where(
                OrganizationMember.org_id == org_id,
                OrganizationMember.role == OrgRole.ORG_ADMIN,
                OrganizationMember.is_active == True,
            )
        )).scalar_one()
        if admin_count == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot delete organization with no admins",
            )
        org.is_active = False
        await self.db.flush()

    async def _require_permission(
        self, org_id: uuid.UUID, user: User, permission: str
    ) -> OrganizationMember:
        from app.db.models.organization import ROLE_PERMISSIONS

        if user.sees_all_orgs:
            return None  # type: ignore[return-value]

        membership = await self._require_membership(org_id, user.id)
        role_perms = ROLE_PERMISSIONS.get(membership.role, set())
        if "*" not in role_perms and permission not in role_perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return membership
