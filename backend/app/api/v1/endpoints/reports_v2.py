"""
Reports persistence API.

GET    /orgs/{org_id}/reports                           list reports
GET    /orgs/{org_id}/reports/{report_id}               get report metadata
DELETE /orgs/{org_id}/reports/{report_id}               delete report record
POST   /orgs/{org_id}/scans/{scan_id}/report/generate   generate + persist scan report
POST   /orgs/{org_id}/projects/{project_id}/reports     generate project-level aggregate report
GET    /orgs/{org_id}/projects/{project_id}/reports     list reports for project
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.db.models.report import Report
from app.db.models.scan import Scan, ScanEngineRun, ScanFinding, ScanStatus
from app.db.models.user import User
from app.db.session import get_db
from app.engines.reporting import ReportFinding, ReportScan, ReportingEngine
from app.schemas.report import GenerateReportRequest, ProjectReportRequest, ReportResponse

router = APIRouter(tags=["reports_v2"])

_TERMINAL = {ScanStatus.COMPLETED, ScanStatus.PARTIAL}
_engine = ReportingEngine()

_CONTENT_TYPES = {
    "json": "application/json",
    "html": "text/html",
    "csv": "text/csv",
}

_CONTENT_DISPOSITION = {
    "json": 'inline; filename="report.json"',
    "html": 'inline; filename="report.html"',
    "csv": 'attachment; filename="findings.csv"',
}


# ── List reports ──────────────────────────────────────────────────────────────

@router.get(
    "/reports",
    response_model=List[ReportResponse],
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def list_reports(
    org_id: uuid.UUID,
    project_id: Optional[uuid.UUID] = Query(None),
    scan_id: Optional[uuid.UUID] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[ReportResponse]:
    q = select(Report).where(Report.org_id == verified_org)
    if project_id:
        q = q.where(Report.project_id == project_id)
    if scan_id:
        q = q.where(Report.scan_id == scan_id)
    q = q.order_by(Report.generated_at.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return [ReportResponse.model_validate(r) for r in result.scalars().all()]


# ── Get report metadata ───────────────────────────────────────────────────────

@router.get(
    "/reports/{report_id}",
    response_model=ReportResponse,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def get_report(
    org_id: uuid.UUID,
    report_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.org_id == verified_org)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return ReportResponse.model_validate(report)


# ── Delete report ─────────────────────────────────────────────────────────────

@router.delete(
    "/reports/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def delete_report(
    org_id: uuid.UUID,
    report_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.org_id == verified_org)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    await db.delete(report)
    await db.commit()


# ── Generate + persist scan report ───────────────────────────────────────────

@router.post(
    "/scans/{scan_id}/report/generate",
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def generate_and_persist_report(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    body: GenerateReportRequest,
    verified_org: uuid.UUID = Depends(get_verified_org),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    # Validate report_type / format
    if body.report_type not in ("executive", "technical", "full"):
        raise HTTPException(status_code=422, detail="Invalid report_type")
    if body.format not in ("json", "html", "csv"):
        raise HTTPException(status_code=422, detail="Invalid format")

    # Fetch scan — tenant isolation enforced
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == verified_org)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")

    if scan.status not in _TERMINAL:
        raise HTTPException(
            status_code=409,
            detail=f"Report unavailable: scan status is '{scan.status.value}'.",
        )

    # Fetch findings + engine runs
    findings_result = await db.execute(
        select(ScanFinding).where(ScanFinding.scan_id == scan_id).order_by(ScanFinding.created_at)
    )
    db_findings = list(findings_result.scalars().all())

    runs_result = await db.execute(
        select(ScanEngineRun).where(ScanEngineRun.scan_id == scan_id).order_by(ScanEngineRun.started_at)
    )
    db_runs = list(runs_result.scalars().all())

    report_findings = [
        ReportFinding(
            id=str(f.id),
            engine=f.engine,
            check_id=f.check_id,
            title=f.title,
            description=f.description,
            risk_level=f.risk_level.value,
            confidence=f.confidence,
            affected_asset=f.affected_asset,
            remediation=f.remediation,
            evidence=f.evidence,
            references=f.references or [],
            status=f.status.value,
            cvss_score=f.cvss_score,
            created_at=f.created_at,
            last_seen_at=f.last_seen_at,
        )
        for f in db_findings
    ]

    report_scan = ReportScan(
        id=str(scan.id),
        org_id=str(scan.org_id),
        target_domain=scan.target_domain,
        status=scan.status.value,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        risk_score=scan.risk_score,
        finding_count=len(db_findings),
        engine_runs=[
            {
                "engine": r.engine,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "finding_count": r.finding_count,
            }
            for r in db_runs
        ],
    )

    chains = [
        {"rule_id": f.check_id, "title": f.title, "description": f.description, "severity": f.risk_level.value}
        for f in report_findings
        if f.engine == "risk_correlation"
    ]
    content_findings = [f for f in report_findings if f.engine != "risk_correlation"]

    content, content_type = _engine.generate(
        scan=report_scan,
        findings=content_findings,
        chains=chains,
        report_type=body.report_type,
        fmt=body.format,
    )

    # Persist report record
    now = datetime.now(timezone.utc)
    report = Report(
        org_id=verified_org,
        project_id=body.project_id or getattr(scan, "project_id", None),
        scan_id=scan_id,
        report_type=body.report_type,
        format=body.format,
        title=body.title or f"{body.report_type.capitalize()} Report — {scan.target_domain}",
        generated_by=current_user.id,
        generated_at=now,
        size_bytes=len(content) if isinstance(content, (bytes, str)) else None,
    )
    db.add(report)
    await db.commit()

    disposition = _CONTENT_DISPOSITION.get(body.format, "inline")
    return Response(
        content=content,
        media_type=content_type,
        headers={
            "Content-Disposition": disposition,
            "X-Report-Id": str(report.id),
        },
    )


# ── Project-level reports ─────────────────────────────────────────────────────

@router.get(
    "/projects/{project_id}/reports",
    response_model=List[ReportResponse],
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def list_project_reports(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[ReportResponse]:
    result = await db.execute(
        select(Report)
        .where(Report.org_id == verified_org, Report.project_id == project_id)
        .order_by(Report.generated_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return [ReportResponse.model_validate(r) for r in result.scalars().all()]


@router.post(
    "/projects/{project_id}/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def create_project_report(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    body: ProjectReportRequest,
    verified_org: uuid.UUID = Depends(get_verified_org),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    """Persist a project-level report record (aggregated, without inline content)."""
    if body.format not in ("json", "html", "csv"):
        raise HTTPException(status_code=422, detail="Invalid format")

    now = datetime.now(timezone.utc)
    report = Report(
        org_id=verified_org,
        project_id=project_id,
        scan_id=None,
        report_type=body.report_type,
        format=body.format,
        title=body.title or f"Project Report — {now.strftime('%Y-%m-%d')}",
        generated_by=current_user.id,
        generated_at=now,
        metadata_={"include_scan_ids": [str(s) for s in (body.include_scan_ids or [])]},
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return ReportResponse.model_validate(report)
