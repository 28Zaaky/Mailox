"""
Findings management API.

GET  /orgs/{org_id}/findings              list with filter + pagination
GET  /orgs/{org_id}/findings/summary      count aggregation
GET  /orgs/{org_id}/findings/{finding_id} single finding
PATCH /orgs/{org_id}/findings/{finding_id} update status
"""
import uuid
from typing import Optional

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.db.models.scan import FindingState, FindingStatus, RiskLevel, Scan, ScanFinding
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.phase5 import (
    FindingListResponse,
    FindingResponse,
    FindingStateUpdate,
    FindingStatusUpdate,
    FindingSummary,
)

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get(
    "",
    response_model=FindingListResponse,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def list_findings(
    org_id: uuid.UUID,
    scan_id: Optional[uuid.UUID] = Query(None),
    engine: Optional[str] = Query(None, max_length=50),
    check_id_prefix: Optional[str] = Query(None, max_length=20),
    risk_level: Optional[RiskLevel] = Query(None),
    finding_status: Optional[FindingStatus] = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> FindingListResponse:
    base = (
        select(ScanFinding)
        .join(Scan, ScanFinding.scan_id == Scan.id)
        .where(Scan.org_id == verified_org)
    )
    if scan_id is not None:
        base = base.where(ScanFinding.scan_id == scan_id)
    if engine is not None:
        base = base.where(ScanFinding.engine == engine)
    if check_id_prefix is not None:
        base = base.where(ScanFinding.check_id.like(f"{check_id_prefix}%"))
    if risk_level is not None:
        base = base.where(ScanFinding.risk_level == risk_level)
    if finding_status is not None:
        base = base.where(ScanFinding.status == finding_status)

    count_q = select(func.count()).select_from(base.subquery())
    total_result = await db.execute(count_q)
    total = total_result.scalar_one()

    offset = (page - 1) * page_size
    items_q = (
        base.order_by(ScanFinding.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    rows = await db.execute(items_q)
    findings = list(rows.scalars().all())

    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/summary",
    response_model=FindingSummary,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def findings_summary(
    org_id: uuid.UUID,
    scan_id: Optional[uuid.UUID] = Query(None),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> FindingSummary:
    base = (
        select(ScanFinding)
        .join(Scan, ScanFinding.scan_id == Scan.id)
        .where(Scan.org_id == verified_org)
    )
    if scan_id is not None:
        base = base.where(ScanFinding.scan_id == scan_id)

    rows = await db.execute(base)
    findings = list(rows.scalars().all())

    by_sev: dict[str, int] = {lvl.value: 0 for lvl in RiskLevel}
    by_status: dict[str, int] = {s.value: 0 for s in FindingStatus}
    by_engine: dict[str, int] = {}

    for f in findings:
        by_sev[f.risk_level.value] = by_sev.get(f.risk_level.value, 0) + 1
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
        by_engine[f.engine] = by_engine.get(f.engine, 0) + 1

    open_crit = sum(
        1 for f in findings
        if f.status == FindingStatus.OPEN and f.risk_level == RiskLevel.CRITICAL
    )
    open_high = sum(
        1 for f in findings
        if f.status == FindingStatus.OPEN and f.risk_level == RiskLevel.HIGH
    )

    return FindingSummary(
        total=len(findings),
        by_severity=by_sev,
        by_status=by_status,
        by_engine=by_engine,
        open_critical=open_crit,
        open_high=open_high,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def get_finding(
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    result = await db.execute(
        select(ScanFinding)
        .join(Scan, ScanFinding.scan_id == Scan.id)
        .where(ScanFinding.id == finding_id, Scan.org_id == verified_org)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return FindingResponse.model_validate(finding)


@router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    dependencies=[Depends(RequirePermission("finding:write"))],
)
async def update_finding_status(
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    # Verify finding belongs to this org
    check = await db.execute(
        select(ScanFinding.id)
        .join(Scan, ScanFinding.scan_id == Scan.id)
        .where(ScanFinding.id == finding_id, Scan.org_id == verified_org)
    )
    if not check.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    await db.execute(
        update(ScanFinding)
        .where(ScanFinding.id == finding_id)
        .values(
            status=body.status,
            status_changed_at=datetime.now(timezone.utc),
            status_changed_by=current_user.id,
        )
    )
    await db.commit()

    result = await db.execute(
        select(ScanFinding).where(ScanFinding.id == finding_id)
    )
    updated = result.scalar_one()
    return FindingResponse.model_validate(updated)


@router.patch(
    "/{finding_id}/state",
    response_model=FindingResponse,
    dependencies=[Depends(RequirePermission("finding:write"))],
)
async def update_finding_state(
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    body: FindingStateUpdate,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    """Transition a finding through its state workflow (open / resolved / accepted_risk / false_positive)."""
    check = await db.execute(
        select(ScanFinding.id)
        .join(Scan, ScanFinding.scan_id == Scan.id)
        .where(ScanFinding.id == finding_id, Scan.org_id == verified_org)
    )
    if not check.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    await db.execute(
        update(ScanFinding)
        .where(ScanFinding.id == finding_id)
        .values(
            state=body.state.value,
            state_note=body.note,
            state_updated_at=datetime.now(timezone.utc),
        )
    )
    await db.commit()

    result = await db.execute(
        select(ScanFinding).where(ScanFinding.id == finding_id)
    )
    updated = result.scalar_one()
    return FindingResponse.model_validate(updated)
