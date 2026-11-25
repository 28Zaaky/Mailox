import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.db.models.finding import CanonicalFinding, FindingStatusHistory
from app.db.models.organization import OrganizationMember
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.finding_canonical import (
    CanonicalFindingResponse,
    CanonicalFindingSummary,
    CanonicalFindingUpdate,
    FindingStatusHistoryEntry,
)

router = APIRouter(tags=["canonical-findings"])

# Valid status transitions
_VALID_TRANSITIONS: dict[str, set] = {
    "open": {"confirmed", "accepted_risk", "in_remediation", "false_positive"},
    "confirmed": {"in_remediation", "accepted_risk", "false_positive", "open"},
    "in_remediation": {"resolved", "open", "confirmed"},
    "accepted_risk": {"open", "confirmed"},
    "false_positive": {"open"},
    "resolved": {"open"},
}


@router.get(
    "/projects/{project_id}/findings",
    response_model=List[CanonicalFindingResponse],
    dependencies=[Depends(RequirePermission("finding:read"))],
)
async def list_project_findings(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[CanonicalFindingResponse]:
    q = select(CanonicalFinding).where(
        CanonicalFinding.org_id == verified_org,
        CanonicalFinding.project_id == project_id,
    )
    if status:
        q = q.where(CanonicalFinding.status == status)
    if risk_level:
        q = q.where(CanonicalFinding.risk_level == risk_level)
    q = q.order_by(CanonicalFinding.last_detected_at.desc()).limit(limit).offset(offset)
    result = await db.execute(q)
    return [CanonicalFindingResponse.model_validate(f) for f in result.scalars().all()]


@router.get(
    "/projects/{project_id}/findings/summary",
    response_model=CanonicalFindingSummary,
    dependencies=[Depends(RequirePermission("finding:read"))],
)
async def get_project_findings_summary(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> CanonicalFindingSummary:
    result = await db.execute(
        select(CanonicalFinding.status, CanonicalFinding.risk_level, func.count())
        .where(
            CanonicalFinding.org_id == verified_org,
            CanonicalFinding.project_id == project_id,
        )
        .group_by(CanonicalFinding.status, CanonicalFinding.risk_level)
    )
    rows = result.all()

    by_status: dict = {}
    by_risk: dict = {}
    total = 0

    for s, r, cnt in rows:
        total += cnt
        by_status[s] = by_status.get(s, 0) + cnt
        by_risk[r] = by_risk.get(r, 0) + cnt

    return CanonicalFindingSummary(total=total, by_status=by_status, by_risk=by_risk)


# Item routes live under /canonical-findings: GET/PATCH /findings/{finding_id}
# is owned by the scan-findings router (used by the frontend), which is
# included first and would shadow these.
@router.get(
    "/canonical-findings/{finding_id}",
    response_model=CanonicalFindingResponse,
    dependencies=[Depends(RequirePermission("finding:read"))],
)
async def get_canonical_finding(
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> CanonicalFindingResponse:
    result = await db.execute(
        select(CanonicalFinding).where(
            CanonicalFinding.id == finding_id,
            CanonicalFinding.org_id == verified_org,
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return CanonicalFindingResponse.model_validate(finding)


@router.patch(
    "/canonical-findings/{finding_id}",
    response_model=CanonicalFindingResponse,
    dependencies=[Depends(RequirePermission("finding:write"))],
)
async def update_canonical_finding(
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    body: CanonicalFindingUpdate,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> CanonicalFindingResponse:
    result = await db.execute(
        select(CanonicalFinding).where(
            CanonicalFinding.id == finding_id,
            CanonicalFinding.org_id == verified_org,
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    prev_status = finding.status

    if body.status and body.status != prev_status:
        allowed = _VALID_TRANSITIONS.get(prev_status, set())
        if body.status not in allowed:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Transition {prev_status!r} → {body.status!r} not allowed",
            )
        finding.status = body.status

        history = FindingStatusHistory(
            id=uuid.uuid4(),
            canonical_finding_id=finding.id,
            actor=current_user.id,
            prev_status=prev_status,
            new_status=body.status,
            reason=body.reason,
            comment=body.comment,
            changed_at=datetime.now(timezone.utc),
        )
        db.add(history)

    if body.assigned_to is not None:
        # Assignee must be an active member of this org (no cross-tenant
        # assignment, no FK violation -> 500 on an unknown UUID)
        member = (await db.execute(
            select(OrganizationMember.id).where(
                OrganizationMember.org_id == verified_org,
                OrganizationMember.user_id == body.assigned_to,
                OrganizationMember.is_active == True,  # noqa: E712
            )
        )).scalar_one_or_none()
        if member is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="assigned_to is not a member of this organization",
            )
        finding.assigned_to = body.assigned_to

    await db.commit()
    await db.refresh(finding)
    return CanonicalFindingResponse.model_validate(finding)


@router.get(
    "/canonical-findings/{finding_id}/history",
    response_model=List[FindingStatusHistoryEntry],
    dependencies=[Depends(RequirePermission("finding:read"))],
)
@router.get(
    "/findings/{finding_id}/history",
    response_model=List[FindingStatusHistoryEntry],
    dependencies=[Depends(RequirePermission("finding:read"))],
)
async def get_finding_history(
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[FindingStatusHistoryEntry]:
    # Verify org ownership first
    exists = await db.execute(
        select(CanonicalFinding.id).where(
            CanonicalFinding.id == finding_id,
            CanonicalFinding.org_id == verified_org,
        )
    )
    if not exists.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    result = await db.execute(
        select(FindingStatusHistory)
        .where(FindingStatusHistory.canonical_finding_id == finding_id)
        .order_by(FindingStatusHistory.changed_at.desc())
    )
    return [FindingStatusHistoryEntry.model_validate(h) for h in result.scalars().all()]
