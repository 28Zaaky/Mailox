"""
Report generation API.

GET /orgs/{org_id}/scans/{scan_id}/report
    ?report_type=executive|technical|full
    &format=json|html|csv
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_verified_org
from app.db.models.scan import Scan, ScanEngineRun, ScanFinding, ScanStatus
from app.db.session import get_db
from app.engines.reporting import ReportFinding, ReportScan, ReportingEngine

router = APIRouter(tags=["reports"])

_TERMINAL = {ScanStatus.COMPLETED, ScanStatus.PARTIAL}
_engine = ReportingEngine()

_CONTENT_DISPOSITION = {
    "json": 'inline; filename="report.json"',
    "html": 'inline; filename="report.html"',
    "csv": 'attachment; filename="findings.csv"',
}


@router.get(
    "/scans/{scan_id}/report",
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def generate_report(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    report_type: str = Query("full", pattern="^(executive|technical|full)$"),
    fmt: str = Query("json", alias="format", pattern="^(json|html|csv)$"),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> Response:
    # Fetch scan — tenant isolation enforced
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == verified_org)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if scan.status not in _TERMINAL:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Report unavailable: scan status is '{scan.status.value}'. "
                   "Wait for scan to reach completed or partial status.",
        )

    # Fetch findings
    findings_result = await db.execute(
        select(ScanFinding)
        .where(ScanFinding.scan_id == scan_id)
        .order_by(ScanFinding.created_at)
    )
    db_findings = list(findings_result.scalars().all())

    # Fetch engine runs
    runs_result = await db.execute(
        select(ScanEngineRun)
        .where(ScanEngineRun.scan_id == scan_id)
        .order_by(ScanEngineRun.started_at)
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

    engine_runs_dicts = [
        {
            "engine": r.engine,
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "finding_count": r.finding_count,
        }
        for r in db_runs
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
        engine_runs=engine_runs_dicts,
    )

    # Correlation chains come from RC-* findings
    chains = [
        {
            "rule_id": f.check_id,
            "title": f.title,
            "description": f.description,
            "severity": f.risk_level.value,
        }
        for f in db_findings
        if f.engine == "risk_correlation"
    ]

    # Non-correlation findings for the report content
    content_findings = [f for f in report_findings if f.engine != "risk_correlation"]

    content, content_type = _engine.generate(
        scan=report_scan,
        findings=content_findings,
        chains=chains,
        report_type=report_type,
        fmt=fmt,
    )

    disposition = _CONTENT_DISPOSITION.get(fmt, "inline")
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": disposition},
    )
