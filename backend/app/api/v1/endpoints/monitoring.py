"""
Monitoring API.

POST   /orgs/{org_id}/projects/{project_id}/monitoring              create schedule
GET    /orgs/{org_id}/projects/{project_id}/monitoring              list schedules
PATCH  /orgs/{org_id}/projects/{project_id}/monitoring/{id}         update schedule
DELETE /orgs/{org_id}/projects/{project_id}/monitoring/{id}         delete schedule
GET    /orgs/{org_id}/projects/{project_id}/monitoring/{id}/history execution history (deltas)
"""
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.db.models.monitoring import MonitoringDelta, MonitoringSchedule
from app.db.models.project import Project
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.monitoring import (
    MonitoringDeltaResponse,
    MonitoringScheduleResponse,
    ScheduleCreate,
    ScheduleUpdate,
)

router = APIRouter(prefix="/projects/{project_id}/monitoring", tags=["monitoring"])


def _cron_next(expr: str) -> datetime:
    """Compute next UTC run time for a cron expression."""
    try:
        from croniter import croniter
        it = croniter(expr, datetime.now(timezone.utc))
        return it.get_next(datetime)
    except Exception:
        return datetime.now(timezone.utc)


async def _get_schedule_or_404(
    db: AsyncSession,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
) -> MonitoringSchedule:
    # First verify project belongs to org
    proj = await db.execute(
        select(Project).where(Project.id == project_id, Project.org_id == org_id)
    )
    if not proj.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    result = await db.execute(
        select(MonitoringSchedule).where(
            MonitoringSchedule.id == schedule_id,
            MonitoringSchedule.project_id == project_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return schedule


@router.post("", response_model=MonitoringScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    project_id: uuid.UUID,
    body: ScheduleCreate,
    org_id: uuid.UUID = Depends(get_verified_org),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RequirePermission("project:write")),
) -> MonitoringScheduleResponse:
    # Verify project belongs to org
    proj = await db.execute(
        select(Project).where(Project.id == project_id, Project.org_id == org_id)
    )
    if not proj.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    schedule = MonitoringSchedule(
        id=uuid.uuid4(),
        project_id=project_id,
        profile_id=body.profile_id,
        cron_expression=body.cron_expression,
        enabled=body.enabled,
        next_run_at=_cron_next(body.cron_expression) if body.enabled else None,
        created_by=current_user.id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return MonitoringScheduleResponse.model_validate(schedule)


@router.get("", response_model=List[MonitoringScheduleResponse])
async def list_schedules(
    project_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RequirePermission("project:read")),
) -> List[MonitoringScheduleResponse]:
    proj = await db.execute(
        select(Project).where(Project.id == project_id, Project.org_id == org_id)
    )
    if not proj.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    result = await db.execute(
        select(MonitoringSchedule)
        .where(MonitoringSchedule.project_id == project_id)
        .order_by(MonitoringSchedule.created_at.desc())
    )
    schedules = result.scalars().all()
    return [MonitoringScheduleResponse.model_validate(s) for s in schedules]


@router.patch("/{schedule_id}", response_model=MonitoringScheduleResponse)
async def update_schedule(
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    body: ScheduleUpdate,
    org_id: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RequirePermission("project:write")),
) -> MonitoringScheduleResponse:
    schedule = await _get_schedule_or_404(db, org_id, project_id, schedule_id)

    if body.cron_expression is not None:
        schedule.cron_expression = body.cron_expression
    if body.enabled is not None:
        schedule.enabled = body.enabled

    # Recompute next_run_at when re-enabling or changing cron
    if schedule.enabled:
        schedule.next_run_at = _cron_next(schedule.cron_expression)
    else:
        schedule.next_run_at = None

    await db.commit()
    await db.refresh(schedule)
    return MonitoringScheduleResponse.model_validate(schedule)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RequirePermission("project:write")),
) -> None:
    schedule = await _get_schedule_or_404(db, org_id, project_id, schedule_id)
    await db.delete(schedule)
    await db.commit()


@router.get("/{schedule_id}/history", response_model=List[MonitoringDeltaResponse])
async def get_history(
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RequirePermission("project:read")),
) -> List[MonitoringDeltaResponse]:
    # Validate access
    await _get_schedule_or_404(db, org_id, project_id, schedule_id)

    result = await db.execute(
        select(MonitoringDelta)
        .where(MonitoringDelta.schedule_id == schedule_id)
        .order_by(MonitoringDelta.computed_at.desc())
        .limit(50)
    )
    deltas = result.scalars().all()
    return [MonitoringDeltaResponse.model_validate(d) for d in deltas]
