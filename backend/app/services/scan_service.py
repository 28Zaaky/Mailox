"""
ScanService — orchestrates scan lifecycle.

- create_and_run_scan: validates, creates Scan(QUEUED) + ScanOutbox atomically,
  dispatches Celery task via _dispatch_task(), returns immediately.
- _dispatch_task: overridable in tests to run engines inline.
- PostgreSQL is source of truth; Celery backend is never queried for scan state.
- cancel_scan: sets cancel_requested=True (cooperative) or CANCELLED directly.
"""
import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import structlog
from fastapi import HTTPException, status
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.db.models.monitoring import MonitoringDelta, MonitoringSchedule
from app.db.models.organization import Organization
from app.db.models.scan import RiskLevel, Scan, ScanFinding, ScanOutbox, ScanStatus, FindingStatus
from app.db.models.user import User
from app.engines.dns_auth import DNSAuthEngine
from app.engines.smtp_discovery import SMTPDiscoveryEngine
from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError
from app.schemas.findings import Finding

logger = structlog.get_logger("mailox.scan_service")

SCANS_PER_ORG_PER_DAY = 20


class ScanService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self._ssrf_guard = SSRFGuard()

    async def create_and_run_scan(
        self,
        org_id: uuid.UUID,
        target_domain: str,
        created_by: uuid.UUID,
        idempotency_key: Optional[str] = None,
        project_id: Optional[uuid.UUID] = None,
        profile_id: Optional[uuid.UUID] = None,
        skip_domain_verification: bool = False,
    ) -> Scan:
        """
        Validate, create Scan(QUEUED) + ScanOutbox atomically, dispatch Celery task.
        Returns immediately — scan completes asynchronously via worker.
        """
        # Idempotency: return existing scan if same key already in progress or done
        if idempotency_key:
            existing = await self._find_by_idempotency_key(org_id, idempotency_key)
            if existing:
                return existing

        await self._check_scan_references(org_id, project_id, profile_id)

        await self._check_quota(org_id)

        # SaaS: ownership proof is mandatory (the worker enforces it too, without
        # exemption). skip_domain_verification is for internal callers/tests only.
        if settings.IS_SAAS and not skip_domain_verification:
            from app.services.domain_verification import DomainVerificationService

            if await DomainVerificationService(self.db).verified_parent(org_id, target_domain) is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Domain not verified: prove you control {target_domain} before scanning it "
                        "(Domains page in the sidebar, then publish the TXT record)."
                    ),
                    headers={"X-Mailox-Error": "domain_not_verified"},
                )

        try:
            await self._ssrf_guard.validate_domain_for_scan(target_domain)
        except SSRFGuardError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Target domain not allowed: {e}",
            )

        # Create scan + outbox atomically
        scan = Scan(
            id=uuid.uuid4(),
            org_id=org_id,
            target_domain=target_domain,
            status=ScanStatus.QUEUED,
            created_by=created_by,
            created_at=datetime.now(timezone.utc),
            idempotency_key=idempotency_key,
            project_id=project_id,
            profile_id=profile_id,
        )
        self.db.add(scan)
        await self.db.flush()

        outbox = ScanOutbox(scan_id=scan.id)
        self.db.add(outbox)
        await self.db.flush()

        # Commit scan + outbox(published=False) BEFORE dispatch so the worker
        # can find the scan in DB immediately — avoids race where Celery picks
        # up the task before the transaction commits.
        await self.db.commit()

        # Dispatch task (overridable for testing)
        task_id = await self._dispatch_task(scan)
        if task_id:
            outbox.celery_task_id = task_id
            outbox.published = True
            outbox.published_at = datetime.now(timezone.utc)
            await self.db.flush()

        # Refresh scan to get current state (inline dispatch may have changed it)
        await self.db.refresh(scan, attribute_names=["findings"])
        return scan

    async def _check_scan_references(
        self,
        org_id: uuid.UUID,
        project_id: Optional[uuid.UUID],
        profile_id: Optional[uuid.UUID],
    ) -> None:
        """Tenant check on client-supplied foreign keys (IDOR guard).

        project_id must belong to org_id; profile_id must be org-owned or a global
        builtin (org_id NULL). Anything else is 404 — same answer as "does not exist",
        so another tenant's IDs cannot be probed.
        """
        from app.db.models.profile import AssessmentProfile
        from app.db.models.project import Project

        not_found = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        if project_id is not None:
            owned = (await self.db.execute(
                select(Project.id).where(Project.id == project_id, Project.org_id == org_id)
            )).scalar_one_or_none()
            if owned is None:
                raise not_found
        if profile_id is not None:
            owned = (await self.db.execute(
                select(AssessmentProfile.id).where(
                    AssessmentProfile.id == profile_id,
                    (AssessmentProfile.org_id == org_id) | AssessmentProfile.org_id.is_(None),
                )
            )).scalar_one_or_none()
            if owned is None:
                raise not_found

    async def _dispatch_task(self, scan: Scan) -> Optional[str]:
        """Dispatch Celery scan task. Override in tests to run engines inline."""
        from app.core.config import settings
        from app.worker.tasks import scan_task

        if settings.DEBUG:
            try:
                task = scan_task.delay(str(scan.id))
                return task.id
            except Exception as exc:
                logger.warning(
                    "celery_dispatch_failed_running_inline",
                    scan_id=str(scan.id),
                    error=str(exc),
                )
                asyncio.create_task(self._run_scan_inline(scan))
                return None

        task = scan_task.delay(str(scan.id))
        return task.id

    async def _run_scan_inline(self, scan: Scan) -> None:
        """Run scan engines inline — used as DEBUG fallback when Celery is unavailable."""
        from app.db.session import AsyncSessionLocal
        from app.engines.risk_correlation import RiskCorrelationEngine

        async with AsyncSessionLocal() as db:
            scan_obj = await db.get(Scan, scan.id)
            if not scan_obj:
                return
            scan_obj.status = ScanStatus.RUNNING
            scan_obj.started_at = datetime.now(timezone.utc)
            await db.commit()

            findings = []
            risk_score: Optional[float] = None
            try:
                findings = await self._run_engines(scan_obj.target_domain)
                # Run risk correlation on collected findings
                corr_engine = RiskCorrelationEngine()
                corr_result = corr_engine.run(scan_obj.target_domain, findings)
                findings = findings + corr_result.findings
                risk_score = corr_result.risk_score
                scan_obj.status = ScanStatus.COMPLETED
            except Exception as exc:
                logger.error("inline_scan_error", scan_id=str(scan.id), error=str(exc))
                scan_obj.status = ScanStatus.FAILED
                scan_obj.error_msg = str(exc)
                findings = []
            finally:
                scan_obj.completed_at = datetime.now(timezone.utc)
                scan_obj.risk_score = risk_score
                scan_obj.progress_pct = 100
                scan_obj.current_engine = None
                now = datetime.now(timezone.utc)
                for finding in findings:
                    evidence = finding.evidence
                    if isinstance(evidence, list):
                        evidence = [e.model_dump(mode="json") if hasattr(e, "model_dump") else e for e in evidence]
                    elif not isinstance(evidence, dict):
                        evidence = {}
                    db.add(ScanFinding(
                        id=uuid.uuid4(),
                        scan_id=scan.id,
                        engine=finding.engine,
                        check_id=finding.check_id,
                        title=finding.title,
                        description=finding.description,
                        risk_level=RiskLevel(finding.risk_level.value),
                        confidence=finding.confidence,
                        evidence=evidence,
                        remediation=finding.remediation,
                        created_at=now,
                        status=FindingStatus.OPEN,
                        affected_asset=getattr(finding, "affected_asset", None),
                        references=getattr(finding, "references", []) or [],
                        last_seen_at=now,
                    ))
                await db.commit()

    async def _run_engines(self, domain: str) -> list[Finding]:
        """Run DNS + SMTP engines concurrently. Used by inline test dispatch."""
        dns_engine = DNSAuthEngine()
        smtp_engine = SMTPDiscoveryEngine()

        results = await asyncio.gather(
            dns_engine.run(domain),
            smtp_engine.run(domain),
            return_exceptions=True,
        )

        all_findings: list[Finding] = []
        for r in results:
            if isinstance(r, Exception):
                logger.error("engine_exception", domain=domain, error=str(r))
            elif hasattr(r, "findings"):
                all_findings.extend(r.findings)
        return all_findings

    async def get_scan(
        self,
        scan_id: uuid.UUID,
        org_id: uuid.UUID,
    ) -> Scan:
        result = await self.db.execute(
            select(Scan)
            .options(selectinload(Scan.findings))
            .options(selectinload(Scan.engine_runs))
            .where(Scan.id == scan_id, Scan.org_id == org_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return scan

    async def list_scans(
        self,
        org_id: uuid.UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> List[tuple[Scan, int]]:
        """Return (scan, finding_count) pairs without loading finding objects."""
        finding_count_sq = (
            select(func.count(ScanFinding.id))
            .where(ScanFinding.scan_id == Scan.id)
            .correlate(Scan)
            .scalar_subquery()
        )
        result = await self.db.execute(
            select(Scan, finding_count_sq.label("finding_count"))
            .where(Scan.org_id == org_id)
            .order_by(Scan.created_at.desc())
            .limit(min(limit, 100))
            .offset(offset)
        )
        return list(result.all())

    async def cancel_scan(
        self,
        scan_id: uuid.UUID,
        org_id: uuid.UUID,
    ) -> Scan:
        """
        Cancel a scan.
        QUEUED → CANCELLED immediately (task not yet running).
        RUNNING → set cancel_requested=True; worker transitions to CANCELLED cooperatively.
        """
        result = await self.db.execute(
            select(Scan)
            .options(selectinload(Scan.findings))
            .where(Scan.id == scan_id, Scan.org_id == org_id)
            .with_for_update()
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

        if scan.status not in (ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Scan is already {scan.status.value}",
            )

        scan.cancel_requested = True

        if scan.status == ScanStatus.RUNNING:
            # Cooperative cancel — worker will finalize transition
            if scan.celery_task_id:
                try:
                    from app.worker.celery_app import celery_app as _celery
                    _celery.control.revoke(scan.celery_task_id, terminate=True)
                except Exception:
                    pass
        else:
            # QUEUED or PENDING — safe to cancel directly
            scan.status = ScanStatus.CANCELLED
            scan.completed_at = datetime.now(timezone.utc)
            scan.error_msg = "Cancelled by user"
            if scan.celery_task_id:
                try:
                    from app.worker.celery_app import celery_app as _celery
                    _celery.control.revoke(scan.celery_task_id, terminate=True)
                except Exception:
                    pass

        await self.db.flush()
        return scan

    async def delete_scan(
        self,
        scan_id: uuid.UUID,
        org_id: uuid.UUID,
    ) -> None:
        result = await self.db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

        _DELETABLE = {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}
        if scan.status not in _DELETABLE:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot delete scan in status '{scan.status.value}'. Cancel it first.",
            )

        # Clear nullable FK references in monitoring tables (no ondelete on these FKs)
        await self.db.execute(
            update(MonitoringSchedule)
            .where(MonitoringSchedule.last_scan_id == scan_id)
            .values(last_scan_id=None)
        )
        await self.db.execute(
            update(MonitoringDelta)
            .where(MonitoringDelta.previous_scan_id == scan_id)
            .values(previous_scan_id=None)
        )
        # Delete monitoring deltas that reference this scan as primary (NOT NULL)
        await self.db.execute(
            delete(MonitoringDelta).where(MonitoringDelta.scan_id == scan_id)
        )

        await self.db.delete(scan)
        await self.db.flush()

    async def get_scan_findings(
        self,
        scan_id: uuid.UUID,
        org_id: uuid.UUID,
    ) -> List[ScanFinding]:
        findings_result = await self.db.execute(
            select(ScanFinding)
            .join(Scan, Scan.id == ScanFinding.scan_id)
            .where(Scan.id == scan_id, Scan.org_id == org_id)
            .order_by(ScanFinding.risk_level.desc(), ScanFinding.created_at)
        )
        findings = list(findings_result.scalars().all())
        if not findings:
            scan_check = await self.db.execute(
                select(Scan.id).where(Scan.id == scan_id, Scan.org_id == org_id)
            )
            if not scan_check.scalar_one_or_none():
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return findings

    async def _check_quota(self, org_id: uuid.UUID) -> None:
        """
        Check daily scan quota with a pessimistic row-level lock on the
        Organization row to prevent concurrent requests from both passing the
        quota check and creating scans that exceed the limit.

        Lock strategy:
          SELECT Organization FOR UPDATE serialises all concurrent quota checks
          for the same org. Because check + INSERT share the same transaction
          (autobegin), the lock is held until the outer commit/rollback.
          Different orgs lock independent rows, so they don't block each other.

        Timezone note:
          "Since 24 hours ago" uses UTC timestamps consistently — both the
          comparison boundary and stored created_at are UTC. No DST ambiguity.
        """
        # Lock the org row — serialises concurrent quota checks for this org
        org_result = await self.db.execute(
            select(Organization)
            .where(Organization.id == org_id, Organization.is_active == True)
            .with_for_update()
        )
        org = org_result.scalar_one_or_none()
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found",
            )

        since = datetime.now(timezone.utc) - timedelta(hours=24)
        result = await self.db.execute(
            select(func.count(Scan.id)).where(
                Scan.org_id == org_id,
                Scan.created_at >= since,
                Scan.status != ScanStatus.CANCELLED,
            )
        )
        count = result.scalar_one()
        quota = org.daily_scan_quota if org.daily_scan_quota is not None else SCANS_PER_ORG_PER_DAY
        if count >= quota:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Daily scan quota exceeded ({quota} scans/day for this organization)",
            )

    async def _find_by_idempotency_key(
        self, org_id: uuid.UUID, key: str
    ) -> Optional[Scan]:
        result = await self.db.execute(
            select(Scan)
            .options(selectinload(Scan.findings))
            .where(
                Scan.org_id == org_id,
                Scan.idempotency_key == key,
                Scan.status.not_in([ScanStatus.FAILED, ScanStatus.CANCELLED]),
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()
