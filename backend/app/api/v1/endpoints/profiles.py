"""
Assessment Profiles API.

GET    /orgs/{org_id}/profiles                  list (builtins + org + project profiles)
POST   /orgs/{org_id}/profiles                  create org-level profile
GET    /orgs/{org_id}/profiles/{profile_id}      get profile
DELETE /orgs/{org_id}/profiles/{profile_id}      delete non-builtin profile
"""
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.db.models.profile import AssessmentProfile
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.profile import ProfileCreate, ProfileResponse

router = APIRouter(prefix="/profiles", tags=["profiles"])


@router.get(
    "",
    response_model=List[ProfileResponse],
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def list_profiles(
    org_id: uuid.UUID,
    project_id: uuid.UUID | None = None,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[ProfileResponse]:
    q = select(AssessmentProfile).where(
        or_(
            AssessmentProfile.org_id.is_(None),          # global builtins
            AssessmentProfile.org_id == verified_org,     # org-level profiles
        )
    )
    if project_id:
        q = q.where(
            or_(
                AssessmentProfile.project_id.is_(None),
                AssessmentProfile.project_id == project_id,
            )
        )
    q = q.order_by(AssessmentProfile.is_builtin.desc(), AssessmentProfile.name)
    result = await db.execute(q)
    return [ProfileResponse.model_validate(p) for p in result.scalars().all()]


@router.post(
    "",
    response_model=ProfileResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def create_profile(
    org_id: uuid.UUID,
    body: ProfileCreate,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ProfileResponse:
    body.validate_engines()
    profile = AssessmentProfile(
        id=uuid.uuid4(),
        org_id=verified_org,
        project_id=body.project_id,
        name=body.name,
        engines=body.engines,
        config=body.config,
        time_limit_seconds=body.time_limit_seconds,
        created_by=current_user.id,
        created_at=datetime.now(timezone.utc),
        is_builtin=False,
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    return ProfileResponse.model_validate(profile)


@router.get(
    "/{profile_id}",
    response_model=ProfileResponse,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def get_profile(
    org_id: uuid.UUID,
    profile_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ProfileResponse:
    result = await db.execute(
        select(AssessmentProfile).where(
            AssessmentProfile.id == profile_id,
            or_(
                AssessmentProfile.org_id.is_(None),
                AssessmentProfile.org_id == verified_org,
            ),
        )
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return ProfileResponse.model_validate(profile)


@router.delete(
    "/{profile_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def delete_profile(
    org_id: uuid.UUID,
    profile_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    result = await db.execute(
        select(AssessmentProfile).where(
            AssessmentProfile.id == profile_id,
            AssessmentProfile.org_id == verified_org,  # only org-owned, not builtins
        )
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    if profile.is_builtin:
        raise HTTPException(status_code=403, detail="Cannot delete built-in profiles")
    await db.delete(profile)
    await db.commit()
