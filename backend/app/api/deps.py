import uuid
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError as JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rate_limiter import check_rate_limit
from app.core.security import decode_access_token
from app.db.models.organization import ROLE_PERMISSIONS, Organization, OrganizationMember
from app.db.models.user import User
from app.db.session import get_db

_bearer = HTTPBearer(auto_error=False)


async def rate_limit_auth(request: Request) -> None:
    """
    Distributed Redis sliding-window rate limiter for auth routes.
    On Redis unavailability: returns HTTP 503 (fail-secure).
    """
    await check_rate_limit(
        request,
        route_category="auth",
        limit=settings.RATE_LIMIT_AUTH_RPM,
        window_seconds=60,
    )


async def rate_limit_refresh(request: Request) -> None:
    """
    Separate, more permissive bucket for /auth/refresh: several tabs or users
    behind one NAT refresh often and must not exhaust the login quota.
    """
    await check_rate_limit(
        request,
        route_category="auth_refresh",
        limit=settings.RATE_LIMIT_AUTH_RPM * 6,
        window_seconds=60,
    )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(credentials.credentials)
        if payload.get("type") != "access":
            raise ValueError("Wrong token type")
        user_id = uuid.UUID(payload["sub"])
    except (JWTError, ValueError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


async def get_verified_org(
    org_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> uuid.UUID:
    """
    Validates org membership from JWT. Returns verified org_id.
    Returns 404 for both not-found and unauthorized — prevents IDOR oracle.
    Platform admins (self-hosted owner) bypass the membership check so they
    can still inspect and reactivate a suspended org; members of an inactive
    org get 404.
    """
    if current_user.sees_all_orgs:
        return org_id

    result = await db.execute(
        select(OrganizationMember)
        .join(Organization, Organization.id == OrganizationMember.org_id)
        .where(
            OrganizationMember.user_id == current_user.id,
            OrganizationMember.org_id == org_id,
            OrganizationMember.is_active == True,
            # A deleted/suspended org must not stay reachable by its members
            Organization.is_active == True,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    return org_id


class RequirePermission:
    """
    FastAPI dependency factory for per-endpoint RBAC.

    Usage:
        router.get("/...", dependencies=[Depends(RequirePermission("finding:write"))])
    """

    def __init__(self, permission: str) -> None:
        self.permission = permission

    async def __call__(
        self,
        org_id: uuid.UUID,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> Optional[OrganizationMember]:
        if current_user.sees_all_orgs:
            return None

        result = await db.execute(
            select(OrganizationMember)
            .join(Organization, Organization.id == OrganizationMember.org_id)
            .where(
                OrganizationMember.user_id == current_user.id,
                OrganizationMember.org_id == org_id,
                OrganizationMember.is_active == True,
                Organization.is_active == True,
            )
        )
        membership = result.scalar_one_or_none()
        if not membership:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

        role_perms = ROLE_PERMISSIONS.get(membership.role, set())
        if "*" not in role_perms and self.permission not in role_perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return membership
