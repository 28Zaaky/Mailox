"""
Scan schedule API — automatic weekly/monthly rescans per domain.

POST   /orgs/{org_id}/schedules         create schedule
GET    /orgs/{org_id}/schedules         list schedules
PATCH  /orgs/{org_id}/schedules/{id}    update (enable/disable, interval)
DELETE /orgs/{org_id}/schedules/{id}    delete
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.db.models.scan_schedule import ScanSchedule, ScheduleInterval
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.scan_schedule import (
    ScanScheduleCreate,
    ScanScheduleResponse,
    ScanScheduleUpdate,
)

router = APIRouter(prefix="/schedules", tags=["schedules"])


def _compute_next_run(interval: str) -> datetime:
    now = datetime.now(timezone.utc)
    if interval == ScheduleInterval.DAILY:
        return now + timedelta(days=1)
    elif interval == ScheduleInterval.WEEKLY:
        return now + timedelta(weeks=1)
    else:  # monthly
        return now + timedelta(days=30)


async def _get_schedule_or_404(
    db: AsyncSession,
    org_id: uuid.UUID,
    schedule_id: uuid.UUID,
) -> ScanSchedule:
    result = await db.execute(
        select(ScanSchedule).where(
            ScanSchedule.id == schedule_id,
            ScanSchedule.org_id == org_id,
        )
    )
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return sched


@router.post(
    "",
    response_model=ScanScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def create_schedule(
    org_id: uuid.UUID,
    body: ScanScheduleCreate,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ScanScheduleResponse:
    sched = ScanSchedule(
        id=uuid.uuid4(),
        org_id=verified_org,
        domain=body.domain,
        interval=body.interval,
        enabled=True,
        next_run_at=_compute_next_run(body.interval),
        created_at=datetime.now(timezone.utc),
        created_by=current_user.id,
    )
    db.add(sched)
    await db.commit()
    await db.refresh(sched)
    return ScanScheduleResponse.model_validate(sched)


@router.get(
    "",
    response_model=List[ScanScheduleResponse],
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def list_schedules(
    org_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[ScanScheduleResponse]:
    result = await db.execute(
        select(ScanSchedule)
        .where(ScanSchedule.org_id == verified_org)
        .order_by(ScanSchedule.created_at.desc())
    )
    schedules = result.scalars().all()
    return [ScanScheduleResponse.model_validate(s) for s in schedules]


@router.patch(
    "/{schedule_id}",
    response_model=ScanScheduleResponse,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def update_schedule(
    org_id: uuid.UUID,
    schedule_id: uuid.UUID,
    body: ScanScheduleUpdate,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ScanScheduleResponse:
    sched = await _get_schedule_or_404(db, verified_org, schedule_id)
    if body.enabled is not None:
        sched.enabled = body.enabled
    if body.interval is not None:
        sched.interval = body.interval
        # Reset next_run_at when interval changes
        sched.next_run_at = _compute_next_run(body.interval)
    await db.commit()
    await db.refresh(sched)
    return ScanScheduleResponse.model_validate(sched)


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def delete_schedule(
    org_id: uuid.UUID,
    schedule_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    sched = await _get_schedule_or_404(db, verified_org, schedule_id)
    await db.delete(sched)
    await db.commit()
