"""
Projects API.

POST   /orgs/{org_id}/projects                              create project
GET    /orgs/{org_id}/projects                              list projects
GET    /orgs/{org_id}/projects/{project_id}                 get project
PATCH  /orgs/{org_id}/projects/{project_id}                 update project
DELETE /orgs/{org_id}/projects/{project_id}                 archive project
GET    /orgs/{org_id}/projects/{project_id}/members         list members
POST   /orgs/{org_id}/projects/{project_id}/members         add member
DELETE /orgs/{org_id}/projects/{project_id}/members/{uid}   remove member
"""
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.db.models.organization import OrganizationMember
from app.db.models.project import Project, ProjectMember
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.project import (
    AddMemberRequest,
    ProjectCreate,
    ProjectMemberResponse,
    ProjectResponse,
    ProjectUpdate,
)

router = APIRouter(prefix="/projects", tags=["projects"])


def _require_project_write(membership: OrganizationMember) -> bool:
    """Returns True if org role permits writing projects."""
    from app.db.models.organization import ROLE_PERMISSIONS
    perms = ROLE_PERMISSIONS.get(membership.role, set())
    return "*" in perms or "project:write" in perms


async def _get_project_or_404(
    db: AsyncSession,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    user: User,
) -> Project:
    """Load project, enforce org ownership + membership visibility."""
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.org_id == org_id,
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if user.sees_all_orgs:
        return project

    # Org admins can see all projects
    org_result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.org_id == org_id,
            OrganizationMember.user_id == user.id,
            OrganizationMember.is_active == True,
        )
    )
    membership = org_result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    from app.db.models.organization import OrgRole
    if membership.role == OrgRole.ORG_ADMIN:
        return project

    # Project member check
    pm_result = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user.id,
        )
    )
    if not pm_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    return project


# ── Create ────────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("project:write"))],
)
async def create_project(
    org_id: uuid.UUID,
    body: ProjectCreate,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ProjectResponse:
    now = datetime.now(timezone.utc)
    project = Project(
        org_id=verified_org,
        name=body.name,
        description=body.description,
        status="active",
        created_by=current_user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(project)
    await db.flush()

    # Auto-add creator as project_manager
    member = ProjectMember(
        project_id=project.id,
        user_id=current_user.id,
        role="project_manager",
        granted_by=current_user.id,
        granted_at=now,
    )
    db.add(member)
    await db.commit()
    await db.refresh(project)
    return ProjectResponse.model_validate(project)


# ── List ──────────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=List[ProjectResponse],
    dependencies=[Depends(RequirePermission("project:read"))],
)
async def list_projects(
    org_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[ProjectResponse]:
    from app.db.models.organization import OrgRole

    # Check if org_admin → see all projects
    org_result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.org_id == verified_org,
            OrganizationMember.user_id == current_user.id,
            OrganizationMember.is_active == True,
        )
    )
    membership = org_result.scalar_one_or_none()
    is_admin = current_user.sees_all_orgs or (
        membership and membership.role == OrgRole.ORG_ADMIN
    )

    if is_admin:
        result = await db.execute(
            select(Project).where(Project.org_id == verified_org).order_by(Project.created_at.desc())
        )
        projects = result.scalars().all()
    else:
        result = await db.execute(
            select(Project)
            .join(ProjectMember, ProjectMember.project_id == Project.id)
            .where(
                Project.org_id == verified_org,
                ProjectMember.user_id == current_user.id,
            )
            .order_by(Project.created_at.desc())
        )
        projects = result.scalars().all()

    return [ProjectResponse.model_validate(p) for p in projects]


# ── Get ───────────────────────────────────────────────────────────────────────

@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    dependencies=[Depends(RequirePermission("project:read"))],
)
async def get_project(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ProjectResponse:
    project = await _get_project_or_404(db, verified_org, project_id, current_user)
    return ProjectResponse.model_validate(project)


# ── Update ────────────────────────────────────────────────────────────────────

@router.patch(
    "/{project_id}",
    response_model=ProjectResponse,
    dependencies=[Depends(RequirePermission("project:write"))],
)
async def update_project(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    body: ProjectUpdate,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ProjectResponse:
    project = await _get_project_or_404(db, verified_org, project_id, current_user)

    if body.name is not None:
        project.name = body.name
    if body.description is not None:
        project.description = body.description
    if body.status is not None:
        project.status = body.status
    project.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(project)
    return ProjectResponse.model_validate(project)


# ── Archive (soft delete) ─────────────────────────────────────────────────────

@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RequirePermission("project:write"))],
)
async def archive_project(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    project = await _get_project_or_404(db, verified_org, project_id, current_user)
    project.status = "archived"
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()


# ── Members — List ────────────────────────────────────────────────────────────

@router.get(
    "/{project_id}/members",
    response_model=List[ProjectMemberResponse],
    dependencies=[Depends(RequirePermission("project:read"))],
)
async def list_project_members(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[ProjectMemberResponse]:
    await _get_project_or_404(db, verified_org, project_id, current_user)

    result = await db.execute(
        select(ProjectMember).where(ProjectMember.project_id == project_id)
    )
    members = result.scalars().all()
    return [ProjectMemberResponse.model_validate(m) for m in members]


# ── Members — Add ─────────────────────────────────────────────────────────────

@router.post(
    "/{project_id}/members",
    response_model=ProjectMemberResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("project:write"))],
)
async def add_project_member(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    body: AddMemberRequest,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ProjectMemberResponse:
    await _get_project_or_404(db, verified_org, project_id, current_user)

    target_user_id = body.user_id

    # Validate target user is org member
    org_member = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.org_id == verified_org,
            OrganizationMember.user_id == target_user_id,
            OrganizationMember.is_active == True,
        )
    )
    if not org_member.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target user is not a member of this organization",
        )

    # Upsert — if already member update role
    existing = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == target_user_id,
        )
    )
    pm = existing.scalar_one_or_none()
    if pm:
        pm.role = body.role
        pm.granted_by = current_user.id
        pm.granted_at = datetime.now(timezone.utc)
    else:
        pm = ProjectMember(
            project_id=project_id,
            user_id=target_user_id,
            role=body.role,
            granted_by=current_user.id,
            granted_at=datetime.now(timezone.utc),
        )
        db.add(pm)

    await db.commit()
    await db.refresh(pm)
    return ProjectMemberResponse.model_validate(pm)


# ── Members — Remove ──────────────────────────────────────────────────────────

@router.delete(
    "/{project_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RequirePermission("project:write"))],
)
async def remove_project_member(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    await _get_project_or_404(db, verified_org, project_id, current_user)

    result = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user_id,
        )
    )
    pm = result.scalar_one_or_none()
    if not pm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

    await db.delete(pm)
    await db.commit()
