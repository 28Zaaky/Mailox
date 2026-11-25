"""
Celery tasks for MAILOX scan workers.

scan_task: runs DNS + SMTP engines for a given scan_id, persists findings.
recover_stalled_scans: beat task that re-queues scans stuck past their lease.
"""
import asyncio
import sys
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from celery.exceptions import Retry, SoftTimeLimitExceeded
from sqlalchemy import exists as sa_exists

from app.worker.celery_app import celery_app
from app.core.config import settings

logger = structlog.get_logger("mailox.worker")

# Windows ProactorEventLoop + asyncpg = broken _proactor on loop close.
# SelectorEventLoop is stable with asyncpg on Windows.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


async def _dispose_loop_bound_resources() -> None:
    """Close every pooled connection created on the current event loop.

    The async SQLAlchemy engine (and the shared Redis client) are module-level and
    pool connections bound to the loop that opened them. Each Celery task runs on
    a fresh loop, so a connection left in the pool by a previous task fails with
    "Future attached to a different loop" (seen on Windows, --pool=solo, on retry).
    """
    from app.db.session import async_engine
    from app.core.redis_client import close_redis

    try:
        await async_engine.dispose()
    except Exception as exc:  # never mask the task's own outcome
        logger.warning("async_engine_dispose_failed", error=str(exc))
    try:
        await close_redis()
    except Exception as exc:
        logger.warning("redis_close_failed", error=str(exc))


def _run_async(coro):
    """Run `coro` to completion on a fresh event loop owned by this call.

    Loop-bound pools are disposed before the loop closes, so the next task (or the
    retry of this one) starts with clean connections on its own loop.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(_dispose_loop_bound_resources())
        finally:
            asyncio.set_event_loop(None)
            loop.close()


async def _mark_scan_failed(scan_id: str, error_msg: str) -> None:
    """Mark a scan FAILED unless it already reached a terminal state.

    Only QUEUED scans, or RUNNING ones whose lease is gone or expired, are touched,
    so a scan another worker is legitimately running is never overwritten.
    """
    from app.db.session import AsyncSessionLocal
    from app.db.models.scan import Scan, ScanStatus
    from sqlalchemy import and_, or_, update

    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Scan)
            .where(
                Scan.id == uuid.UUID(scan_id),
                or_(
                    Scan.status == ScanStatus.QUEUED,
                    and_(
                        Scan.status == ScanStatus.RUNNING,
                        or_(Scan.worker_lease_id.is_(None), Scan.lease_expires_at < now),
                    ),
                ),
            )
            .values(
                status=ScanStatus.FAILED,
                completed_at=now,
                error_msg=error_msg[:500],
                current_engine=None,
                worker_lease_id=None,
                lease_expires_at=None,
            )
        )
        await db.commit()


@celery_app.task(
    name="mailox.scan_task",
    bind=True,
    max_retries=settings.SCAN_TASK_MAX_RETRIES,
    default_retry_delay=settings.SCAN_TASK_RETRY_COUNTDOWN,
    reject_on_worker_lost=True,
)
def scan_task(self, scan_id: str) -> None:
    try:
        _run_async(_run_scan(scan_id, self))
    except (Retry, SoftTimeLimitExceeded):
        raise
    except Exception as exc:
        # Either a failure outside _run_scan's own handler (e.g. DB error while
        # acquiring the lease, before any status change), or _run_scan's handler
        # could not schedule its retry (scan reset to QUEUED), or retries are
        # exhausted. Retry while attempts remain; otherwise never leave the scan
        # stuck in QUEUED/RUNNING without an explanation.
        logger.error("scan_task_failed", scan_id=scan_id, error=str(exc))
        if self.request.retries < self.max_retries:
            try:
                raise self.retry(exc=exc)
            except Retry:
                raise
            except Exception as retry_exc:
                reason = f"Retry could not be scheduled: {type(retry_exc).__name__}"
        else:
            reason = f"Unexpected error: {type(exc).__name__} (retries exhausted)"
        try:
            _run_async(_mark_scan_failed(scan_id, reason))
        except Exception as mark_exc:
            logger.error("scan_mark_failed_error", scan_id=scan_id, error=str(mark_exc))
        raise


@celery_app.task(name="mailox.recover_stalled_scans")
def recover_stalled_scans() -> None:
    _run_async(_recover_stalled())


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _get_target_domain(scan_id: str) -> Optional[str]:
    """Fetch target_domain in a fresh session (worker context, no request session)."""
    from app.db.session import AsyncSessionLocal
    from app.db.models.scan import Scan
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan.target_domain).where(Scan.id == uuid.UUID(scan_id))
        )
        row = result.fetchone()
        return row[0] if row else None


# ── Async scan implementation ─────────────────────────────────────────────────


async def _run_scan(scan_id: str, task) -> None:
    from app.db.session import AsyncSessionLocal
    from app.db.models.scan import Scan, ScanFinding, ScanStatus, RiskLevel, ScanEngineRun
    from app.engines.dns_auth import DNSAuthEngine
    from app.engines.smtp_discovery import SMTPDiscoveryEngine
    from app.engines.smtp_security import SMTPSecurityEngine
    from sqlalchemy import select, update

    lease_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    lease_expires = now + timedelta(seconds=settings.WORKER_LEASE_DURATION_SECONDS)

    # ── BUG-02: atomic lease acquisition ─────────────────────────────────────
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            update(Scan)
            .where(Scan.id == uuid.UUID(scan_id), Scan.status == ScanStatus.QUEUED)
            .values(
                status=ScanStatus.RUNNING,
                worker_lease_id=lease_id,
                lease_expires_at=lease_expires,
                heartbeat_at=now,
                started_at=now,
                current_engine=None,
                progress_pct=5,
                attempt_number=Scan.attempt_number + 1,
            )
            .returning(Scan.attempt_number, Scan.cancel_requested, Scan.target_domain)
        )
        row = result.fetchone()
        if not row:
            # Lease not acquired: scan already RUNNING (another worker) or terminal
            logger.info("lease_not_acquired", scan_id=scan_id)
            await db.rollback()
            return
        attempt_number, cancel_requested, target_domain = row
        await db.commit()

    # ── SaaS: the org must have proven it controls the domain ────────────────
    # Checked here as well as in the API so scheduled and monitoring scans, which
    # are created by the worker, cannot reach an unverified domain either.
    if settings.IS_SAAS:
        from app.db.models.organization import OrganizationMember
        from app.db.models.user import User
        from app.services.domain_verification import DomainVerificationService

        async with AsyncSessionLocal() as db:
            org_row = await db.execute(select(Scan.org_id).where(Scan.id == uuid.UUID(scan_id)))
            scan_org_id = org_row.scalar_one()
            # Suspending an account must also stop the scheduled scans it left behind
            active_member = (await db.execute(
                select(OrganizationMember.id)
                .join(User, User.id == OrganizationMember.user_id)
                .where(
                    OrganizationMember.org_id == scan_org_id,
                    OrganizationMember.is_active == True,  # noqa: E712
                    User.is_active == True,  # noqa: E712
                )
                .limit(1)
            )).scalar_one_or_none()
            from app.db.models.organization import Organization as _GateOrg
            org_active = (await db.execute(
                select(_GateOrg.is_active).where(_GateOrg.id == scan_org_id)
            )).scalar_one_or_none()
            block_reason = None
            if not org_active:
                block_reason = "Organization deactivated"
            elif active_member is None:
                block_reason = "No active account in this organization"
            elif await DomainVerificationService(db).verified_parent(scan_org_id, target_domain) is None:
                block_reason = "Domain ownership not verified for this organization"
            if block_reason:
                await db.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                    .values(
                        status=ScanStatus.FAILED,
                        completed_at=datetime.now(timezone.utc),
                        error_msg=block_reason,
                        current_engine=None,
                        worker_lease_id=None,
                    )
                )
                await db.commit()
                logger.warning("scan_blocked_saas", scan_id=scan_id, domain=target_domain, reason=block_reason)
                return

    # ── Capture scope snapshot at scan start ──────────────────────────────────
    async with AsyncSessionLocal() as db:
        from app.db.models.asset import ScopeSnapshot
        from app.db.models.scan import Scan as _Scan
        from sqlalchemy.dialects.postgresql import insert as _pg_insert
        from sqlalchemy import select as _select

        meta = await db.execute(
            _select(_Scan.project_id, _Scan.org_id).where(_Scan.id == uuid.UUID(scan_id))
        )
        meta_row = meta.fetchone()
        _project_id = meta_row[0] if meta_row else None
        _org_id = meta_row[1] if meta_row else None

        # Load org-level pentest config
        _org_pentest_cfg: dict = {}
        # A platform admin can withdraw the offensive modules from an organization
        _offensive_allowed = True
        if _org_id:
            from app.db.models.organization import Organization as _Org
            _org_row = await db.execute(
                _select(_Org.pentest_config, _Org.offensive_modules_allowed).where(_Org.id == _org_id)
            )
            _org_cfg = _org_row.one_or_none()
            if _org_cfg:
                if _org_cfg[0]:
                    _org_pentest_cfg = dict(_org_cfg[0])
                _offensive_allowed = bool(_org_cfg[1])

        if _project_id:
            from app.db.models.asset import ProjectAsset, Asset
            from app.db.models.project import Project as _Project
            # Tenant guard (defence in depth): only read scope from a project owned
            # by the scan's org, even if a foreign project_id reached the scan row.
            scope_rows = await db.execute(
                _select(ProjectAsset, Asset)
                .join(Asset, Asset.id == ProjectAsset.asset_id)
                .join(_Project, _Project.id == ProjectAsset.project_id)
                .where(ProjectAsset.project_id == _project_id, _Project.org_id == _org_id)
            )
            targets = [
                {"type": a.asset_type, "value": a.value, "authorized": pa.authorized}
                for pa, a in scope_rows.all()
            ]
        else:
            targets = [{"type": "domain", "value": target_domain, "authorized": True}]

        existing_snap = await db.execute(
            _select(ScopeSnapshot).where(ScopeSnapshot.scan_id == uuid.UUID(scan_id))
        )
        if not existing_snap.scalar_one_or_none():
            snap = ScopeSnapshot(
                id=uuid.uuid4(),
                scan_id=uuid.UUID(scan_id),
                targets=targets,
                captured_at=datetime.now(timezone.utc),
            )
            db.add(snap)
            await db.commit()

    if cancel_requested:
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(Scan)
                .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                .values(
                    status=ScanStatus.CANCELLED,
                    completed_at=datetime.now(timezone.utc),
                    error_msg="Cancelled by user",
                    current_engine=None,
                    worker_lease_id=None,
                )
            )
            await db.commit()
        return

    # ── Heartbeat task ────────────────────────────────────────────────────────
    heartbeat_stop = asyncio.Event()

    async def _heartbeat():
        while not heartbeat_stop.is_set():
            await asyncio.sleep(settings.WORKER_HEARTBEAT_INTERVAL_SECONDS)
            if heartbeat_stop.is_set():
                break
            try:
                async with AsyncSessionLocal() as hb_db:
                    new_expires = datetime.now(timezone.utc) + timedelta(
                        seconds=settings.WORKER_LEASE_DURATION_SECONDS
                    )
                    await hb_db.execute(
                        update(Scan)
                        .where(
                            Scan.id == uuid.UUID(scan_id),
                            Scan.worker_lease_id == lease_id,
                        )
                        .values(
                            lease_expires_at=new_expires,
                            heartbeat_at=datetime.now(timezone.utc),
                        )
                    )
                    await hb_db.commit()
            except Exception as hb_exc:
                logger.warning("heartbeat_failed", scan_id=scan_id, error=str(hb_exc))

    heartbeat_task = asyncio.create_task(_heartbeat())

    # ── Load assessment profile ───────────────────────────────────────────────
    _all_engines = [
        "dns_auth", "smtp_discovery", "smtp_security", "webmail", "vuln_intel",
        "secrets", "web_security", "web_pentest",
    ]
    engines_to_run: list[str] = _all_engines
    scan_timeout = settings.SCAN_TASK_TIMEOUT_SECONDS

    async with AsyncSessionLocal() as db:
        profile_row = await db.execute(
            select(Scan.profile_id, Scan.org_id).where(Scan.id == uuid.UUID(scan_id))
        )
        _prof_meta = profile_row.one_or_none()
        profile_id_val, _prof_org_id = (_prof_meta[0], _prof_meta[1]) if _prof_meta else (None, None)
        if profile_id_val:
            from app.db.models.profile import AssessmentProfile
            # Tenant guard: org-owned profile or global builtin (org_id NULL) only
            prof_row = await db.execute(
                select(AssessmentProfile).where(
                    AssessmentProfile.id == profile_id_val,
                    (AssessmentProfile.org_id == _prof_org_id) | AssessmentProfile.org_id.is_(None),
                )
            )
            prof = prof_row.scalar_one_or_none()
            if prof and prof.engines:
                engines_to_run = [e for e in prof.engines if e in _all_engines]
            if prof and prof.time_limit_seconds:
                scan_timeout = prof.time_limit_seconds

    # ── Load per-org effective settings (overrides .env) ─────────────────────
    _eff_settings = None
    if _org_id:
        try:
            from app.core.org_settings_resolver import get_effective_settings as _get_eff
            async with AsyncSessionLocal() as db:
                _eff_settings = await _get_eff(db, _org_id)
            # Allow org to override scan_timeout from profile / global default
            if _eff_settings.scan_timeout:
                scan_timeout = _eff_settings.scan_timeout
        except Exception as _eff_exc:
            logger.warning("org_settings_load_failed", scan_id=scan_id, error=str(_eff_exc))

    half_timeout = scan_timeout / 2.0
    dns_findings = []
    smtp_findings = []
    smtp_security_findings: list = []
    webmail_findings = []
    vuln_intel_findings = []
    secrets_findings = []
    web_security_findings = []
    active_probes_findings = []
    canary_probes_findings = []
    cred_probes_findings = []
    web_pentest_findings: list = []
    dns_failed = False
    smtp_failed = False
    webmail_failed = False
    vuln_intel_failed = False
    secrets_failed = False
    active_probes_failed = False
    canary_probes_failed = False
    cred_probes_failed = False
    web_pentest_failed = False
    smtp_security_failed = False
    # Counts only real crashes (Exception), not timeouts (not applicable for domain)
    aux_error_count = 0

    try:
        # ── DNS engine ────────────────────────────────────────────────────────
        try:
            async with AsyncSessionLocal() as db:
                # BUG-11: guard INSERT — abort if lease stolen before DNS run
                lease_check = await db.execute(
                    select(Scan.id).where(
                        Scan.id == uuid.UUID(scan_id),
                        Scan.worker_lease_id == lease_id,
                    )
                )
                if not lease_check.fetchone():
                    logger.warning("lease_stolen_before_dns_run", scan_id=scan_id)
                    return
                if "dns_auth" in engines_to_run:
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="dns_auth",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="dns_auth")
                    )
                await db.commit()

            if "dns_auth" in engines_to_run:
                dns_engine = DNSAuthEngine()
                dns_result = await asyncio.wait_for(
                    dns_engine.run(target_domain),
                    timeout=half_timeout,
                )
                dns_findings = dns_result.findings if hasattr(dns_result, "findings") else []

                async with AsyncSessionLocal() as db:
                    # BUG-12: guard UPDATE with EXISTS(lease still valid)
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.scan_id == uuid.UUID(scan_id),
                            ScanEngineRun.attempt_number == attempt_number,
                            ScanEngineRun.engine == "dns_auth",
                            sa_exists(
                                select(Scan.id).where(
                                    Scan.id == uuid.UUID(scan_id),
                                    Scan.worker_lease_id == lease_id,
                                )
                            ),
                        )
                        .values(
                            status="completed",
                            finished_at=datetime.now(timezone.utc),
                            finding_count=len(dns_findings),
                        )
                    )
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(progress_pct=50)
                    )
                    await db.commit()

        except asyncio.TimeoutError:
            dns_failed = True
            logger.warning("dns_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "dns_auth",
                        sa_exists(
                            select(Scan.id).where(
                                Scan.id == uuid.UUID(scan_id),
                                Scan.worker_lease_id == lease_id,
                            )
                        ),
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            dns_failed = True
            logger.error("dns_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "dns_auth",
                        sa_exists(
                            select(Scan.id).where(
                                Scan.id == uuid.UUID(scan_id),
                                Scan.worker_lease_id == lease_id,
                            )
                        ),
                    )
                    .values(
                        status="failed",
                        finished_at=datetime.now(timezone.utc),
                        error_msg=str(exc)[:500],
                    )
                )
                await db.commit()

        # Cancel checkpoint after DNS
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan.cancel_requested, Scan.status)
                .where(Scan.id == uuid.UUID(scan_id))
            )
            check = result.fetchone()
        if check and (check[0] or check[1] == ScanStatus.CANCELLED):
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                    .values(
                        status=ScanStatus.CANCELLED,
                        completed_at=datetime.now(timezone.utc),
                        error_msg="Cancelled by user",
                        current_engine=None,
                        worker_lease_id=None,
                    )
                )
                await db.commit()
            return

        # ── SMTP engine ───────────────────────────────────────────────────────
        try:
            async with AsyncSessionLocal() as db:
                # BUG-11: guard INSERT — abort if lease stolen before SMTP run
                lease_check = await db.execute(
                    select(Scan.id).where(
                        Scan.id == uuid.UUID(scan_id),
                        Scan.worker_lease_id == lease_id,
                    )
                )
                if not lease_check.fetchone():
                    logger.warning("lease_stolen_before_smtp_run", scan_id=scan_id)
                    return
                if "smtp_discovery" in engines_to_run:
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="smtp_discovery",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="smtp_discovery", progress_pct=55)
                    )
                await db.commit()

            if "smtp_discovery" in engines_to_run:
                smtp_engine = SMTPDiscoveryEngine()
                smtp_result = await asyncio.wait_for(
                    smtp_engine.run(target_domain),
                    timeout=half_timeout,
                )
                smtp_findings = smtp_result.findings if hasattr(smtp_result, "findings") else []

                async with AsyncSessionLocal() as db:
                    # BUG-12: guard UPDATE with EXISTS(lease still valid)
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.scan_id == uuid.UUID(scan_id),
                            ScanEngineRun.attempt_number == attempt_number,
                            ScanEngineRun.engine == "smtp_discovery",
                            sa_exists(
                                select(Scan.id).where(
                                    Scan.id == uuid.UUID(scan_id),
                                    Scan.worker_lease_id == lease_id,
                                )
                            ),
                        )
                        .values(
                            status="completed",
                            finished_at=datetime.now(timezone.utc),
                            finding_count=len(smtp_findings),
                        )
                    )
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(progress_pct=65)
                    )
                    await db.commit()

        except asyncio.TimeoutError:
            smtp_failed = True
            logger.warning("smtp_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "smtp_discovery",
                        sa_exists(
                            select(Scan.id).where(
                                Scan.id == uuid.UUID(scan_id),
                                Scan.worker_lease_id == lease_id,
                            )
                        ),
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            smtp_failed = True
            logger.error("smtp_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "smtp_discovery",
                        sa_exists(
                            select(Scan.id).where(
                                Scan.id == uuid.UUID(scan_id),
                                Scan.worker_lease_id == lease_id,
                            )
                        ),
                    )
                    .values(
                        status="failed",
                        finished_at=datetime.now(timezone.utc),
                        error_msg=str(exc)[:500],
                    )
                )
                await db.commit()

        # ── smtp_security ─────────────────────────────────────────────────────
        smtp_security_findings: list = []
        if not smtp_failed and "smtp_security" in engines_to_run:
            try:
                async with AsyncSessionLocal() as db:
                    result_check = await db.execute(
                        select(Scan.id).where(
                            Scan.id == uuid.UUID(scan_id),
                            Scan.worker_lease_id == lease_id,
                        )
                    )
                    if not result_check.fetchone():
                        logger.warning("lease_stolen_before_smtp_security", scan_id=scan_id)
                        return
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="smtp_security",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="smtp_security", progress_pct=68)
                    )
                    await db.commit()

                smtp_sec_engine = SMTPSecurityEngine()
                # Inject probe data gathered by smtp_discovery to avoid duplicate network calls
                try:
                    _probe_data = (smtp_result.metadata or {}).get("probes", [])
                except NameError:
                    _probe_data = []
                smtp_sec_engine._smtp_probe_data = _probe_data  # type: ignore[attr-defined]

                smtp_sec_result = await asyncio.wait_for(
                    smtp_sec_engine.run(target_domain),
                    timeout=30.0,
                )
                smtp_security_findings = smtp_sec_result.findings if hasattr(smtp_sec_result, "findings") else []

                async with AsyncSessionLocal() as db:
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.scan_id == uuid.UUID(scan_id),
                            ScanEngineRun.attempt_number == attempt_number,
                            ScanEngineRun.engine == "smtp_security",
                            sa_exists(
                                select(Scan.id).where(
                                    Scan.id == uuid.UUID(scan_id),
                                    Scan.worker_lease_id == lease_id,
                                )
                            ),
                        )
                        .values(
                            status="completed",
                            finished_at=datetime.now(timezone.utc),
                            finding_count=len(smtp_security_findings),
                        )
                    )
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(progress_pct=72)
                    )
                    await db.commit()

            except Exception as exc:
                smtp_security_failed = True
                aux_error_count += 1
                logger.error("smtp_security_engine_error", scan_id=scan_id, error=str(exc))
                async with AsyncSessionLocal() as db:
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.scan_id == uuid.UUID(scan_id),
                            ScanEngineRun.attempt_number == attempt_number,
                            ScanEngineRun.engine == "smtp_security",
                            sa_exists(
                                select(Scan.id).where(
                                    Scan.id == uuid.UUID(scan_id),
                                    Scan.worker_lease_id == lease_id,
                                )
                            ),
                        )
                        .values(
                            status="failed",
                            finished_at=datetime.now(timezone.utc),
                            error_msg=str(exc)[:500],
                        )
                    )
                    await db.commit()

        # Cancel checkpoint after SMTP
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan.cancel_requested, Scan.status)
                .where(Scan.id == uuid.UUID(scan_id))
            )
            check = result.fetchone()
        if check and (check[0] or check[1] == ScanStatus.CANCELLED):
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                    .values(
                        status=ScanStatus.CANCELLED,
                        completed_at=datetime.now(timezone.utc),
                        error_msg="Cancelled by user",
                        current_engine=None,
                        worker_lease_id=None,
                    )
                )
                await db.commit()
            return

        # ── WebmailEngine ─────────────────────────────────────────────────────
        try:
            from app.engines.webmail import WebmailEngine
            async with AsyncSessionLocal() as db:
                lease_check = await db.execute(
                    select(Scan.id).where(
                        Scan.id == uuid.UUID(scan_id),
                        Scan.worker_lease_id == lease_id,
                    )
                )
                if not lease_check.fetchone():
                    logger.warning("lease_stolen_before_webmail_run", scan_id=scan_id)
                    return
                if "webmail" in engines_to_run:
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="webmail",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="webmail", progress_pct=70)
                    )
                await db.commit()

            if "webmail" in engines_to_run:
                webmail_engine = WebmailEngine()
                webmail_result = await asyncio.wait_for(
                    webmail_engine.run(target_domain),
                    timeout=half_timeout,
                )
                webmail_findings = webmail_result.findings if hasattr(webmail_result, "findings") else []

                async with AsyncSessionLocal() as db:
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.scan_id == uuid.UUID(scan_id),
                            ScanEngineRun.attempt_number == attempt_number,
                            ScanEngineRun.engine == "webmail",
                            sa_exists(
                                select(Scan.id).where(
                                    Scan.id == uuid.UUID(scan_id),
                                    Scan.worker_lease_id == lease_id,
                                )
                            ),
                        )
                        .values(
                            status="completed",
                            finished_at=datetime.now(timezone.utc),
                            finding_count=len(webmail_findings),
                        )
                    )
                    await db.commit()

        except asyncio.TimeoutError:
            webmail_failed = True
            logger.warning("webmail_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "webmail",
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            webmail_failed = True
            aux_error_count += 1
            logger.error("webmail_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "webmail",
                    )
                    .values(status="failed", finished_at=datetime.now(timezone.utc), error_msg=str(exc)[:500])
                )
                await db.commit()

        # ── VulnIntelEngine (post-processing) ─────────────────────────────────
        try:
            from app.engines.vuln_intel import VulnIntelEngine
            async with AsyncSessionLocal() as db:
                lease_check = await db.execute(
                    select(Scan.id).where(
                        Scan.id == uuid.UUID(scan_id),
                        Scan.worker_lease_id == lease_id,
                    )
                )
                if not lease_check.fetchone():
                    logger.warning("lease_stolen_before_vuln_intel_run", scan_id=scan_id)
                    return
                if "vuln_intel" in engines_to_run:
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="vuln_intel",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="vuln_intel", progress_pct=85)
                    )
                await db.commit()

            if "vuln_intel" in engines_to_run:
                vuln_engine = VulnIntelEngine()
                if _eff_settings:
                    vuln_engine._nvd_api_key = _eff_settings.nvd_api_key
                prior_findings = dns_findings + smtp_findings + webmail_findings
                async with AsyncSessionLocal() as _vuln_db:
                    vuln_result = await asyncio.wait_for(
                        vuln_engine.run_from_findings(target_domain, prior_findings, db=_vuln_db),
                        timeout=half_timeout,
                    )
                vuln_intel_findings = vuln_result.findings if hasattr(vuln_result, "findings") else []

                async with AsyncSessionLocal() as db:
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.scan_id == uuid.UUID(scan_id),
                            ScanEngineRun.attempt_number == attempt_number,
                            ScanEngineRun.engine == "vuln_intel",
                            sa_exists(
                                select(Scan.id).where(
                                    Scan.id == uuid.UUID(scan_id),
                                    Scan.worker_lease_id == lease_id,
                                )
                            ),
                        )
                        .values(
                            status="completed",
                            finished_at=datetime.now(timezone.utc),
                            finding_count=len(vuln_intel_findings),
                        )
                    )
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(progress_pct=95)
                    )
                    await db.commit()

        except asyncio.TimeoutError:
            vuln_intel_failed = True
            logger.warning("vuln_intel_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "vuln_intel",
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            vuln_intel_failed = True
            aux_error_count += 1
            logger.error("vuln_intel_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "vuln_intel",
                    )
                    .values(status="failed", finished_at=datetime.now(timezone.utc), error_msg=str(exc)[:500])
                )
                await db.commit()

        # ── SecretsEngine (HIBP domain breach lookup) ────────────────────────
        try:
            from app.engines.secrets import SecretsEngine
            async with AsyncSessionLocal() as db:
                lease_check = await db.execute(
                    select(Scan.id).where(
                        Scan.id == uuid.UUID(scan_id),
                        Scan.worker_lease_id == lease_id,
                    )
                )
                if not lease_check.fetchone():
                    logger.warning("lease_stolen_before_secrets", scan_id=scan_id)
                    return
                if "secrets" in engines_to_run:
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="secrets",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="secrets", progress_pct=93)
                    )
                await db.commit()

            if "secrets" in engines_to_run:
                secrets_engine = SecretsEngine()
                if _eff_settings:
                    secrets_engine._github_token = _eff_settings.github_token
                    secrets_engine._intelx_api_key = _eff_settings.intelx_api_key
                secrets_result = await asyncio.wait_for(
                    secrets_engine.run(target_domain),
                    timeout=20.0,
                )
                secrets_findings = secrets_result.findings if secrets_result.success else []

                async with AsyncSessionLocal() as db:
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.scan_id == uuid.UUID(scan_id),
                            ScanEngineRun.attempt_number == attempt_number,
                            ScanEngineRun.engine == "secrets",
                        )
                        .values(
                            status="completed",
                            finished_at=datetime.now(timezone.utc),
                            finding_count=len(secrets_findings),
                        )
                    )
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id))
                        .values(progress_pct=95)
                    )
                    await db.commit()

        except asyncio.TimeoutError:
            secrets_failed = True
            logger.warning("secrets_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "secrets",
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            secrets_failed = True
            aux_error_count += 1
            logger.error("secrets_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "secrets",
                    )
                    .values(status="failed", finished_at=datetime.now(timezone.utc), error_msg=str(exc)[:500])
                )
                await db.commit()

        # ── WebSecurityEngine (HTTP security headers, TLS, OWASP) ────────────
        web_security_failed = False
        try:
            from app.engines.web_security import WebSecurityEngine
            async with AsyncSessionLocal() as db:
                lease_check = await db.execute(
                    select(Scan.id).where(
                        Scan.id == uuid.UUID(scan_id),
                        Scan.worker_lease_id == lease_id,
                    )
                )
                if not lease_check.fetchone():
                    logger.warning("lease_stolen_before_web_security", scan_id=scan_id)
                    return
                web_security_run_id = None
                if "web_security" in engines_to_run:
                    web_security_run_id = uuid.uuid4()
                    db.add(ScanEngineRun(
                        id=web_security_run_id,
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="web_security",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    ))
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="web_security")
                    )
                await db.commit()

            if "web_security" in engines_to_run:
                ws_engine = WebSecurityEngine()
                ws_result = await asyncio.wait_for(
                    ws_engine.run(target_domain),
                    timeout=45.0,
                )
                web_security_findings = ws_result.findings if ws_result.success else []

                async with AsyncSessionLocal() as db:
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.id == web_security_run_id,
                            sa_exists().where(
                                Scan.id == uuid.UUID(scan_id),
                                Scan.worker_lease_id == lease_id,
                            ),
                        )
                        .values(
                            status="completed",
                            finished_at=datetime.now(timezone.utc),
                            finding_count=len(web_security_findings),
                        )
                    )
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id))
                        .values(progress_pct=97)
                    )
                    await db.commit()

        except asyncio.TimeoutError:
            web_security_failed = True
            logger.warning("web_security_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "web_security",
                        ScanEngineRun.status == "running",
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            web_security_failed = True
            aux_error_count += 1
            logger.error("web_security_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "web_security",
                        ScanEngineRun.status == "running",
                    )
                    .values(status="failed", finished_at=datetime.now(timezone.utc), error_msg=str(exc)[:500])
                )
                await db.commit()

        # ── ActiveProbesEngine ────────────────────────────────────────────────
        try:
            from app.engines.active_probes import ActiveProbesEngine
            async with AsyncSessionLocal() as db:
                lease_check = await db.execute(
                    select(Scan.id).where(
                        Scan.id == uuid.UUID(scan_id),
                        Scan.worker_lease_id == lease_id,
                    )
                )
                if not lease_check.fetchone():
                    logger.warning("lease_stolen_before_active_probes", scan_id=scan_id)
                    return
                if "active_probes" in engines_to_run:
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="active_probes",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="active_probes", progress_pct=96)
                    )
                await db.commit()

            prior_for_probes = dns_findings + smtp_findings + smtp_security_findings + webmail_findings + vuln_intel_findings
            # Extract SMTP host and connected port from smtp_findings affected_asset
            _mx_host = None
            _smtp_connected_port = 587
            for _f in smtp_findings:
                _asset = getattr(_f, "affected_asset", None) or ""
                if not _asset:
                    continue
                _parts = _asset.split(":")
                _host_part = _parts[0]
                if _host_part and _host_part != target_domain:
                    _mx_host = _host_part
                    if len(_parts) > 1:
                        try:
                            _smtp_connected_port = int(_parts[1])
                        except (ValueError, IndexError):
                            pass
                    break
            # Extract webmail URL from webmail_findings
            _webmail_url = None
            for _f in webmail_findings:
                _asset = getattr(_f, "affected_asset", None) or ""
                if _asset.startswith("http"):
                    _webmail_url = _asset
                    break

            if _offensive_allowed:
                probes_engine = ActiveProbesEngine()
                probes_result = await asyncio.wait_for(
                    probes_engine.run_from_findings(
                        domain=target_domain,
                        prior_findings=prior_for_probes,
                        mx_host=_mx_host,
                        webmail_url=_webmail_url,
                        smtp_port=_smtp_connected_port,
                    ),
                    timeout=60.0,
                )
                active_probes_findings = probes_result.findings if probes_result.success else []
            else:
                active_probes_findings = []
                logger.info("active_probes_skipped", scan_id=scan_id, reason="offensive modules disabled for org")

            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "active_probes",
                        sa_exists(
                            select(Scan.id).where(
                                Scan.id == uuid.UUID(scan_id),
                                Scan.worker_lease_id == lease_id,
                            )
                        ),
                    )
                    .values(
                        status="completed",
                        finished_at=datetime.now(timezone.utc),
                        finding_count=len(active_probes_findings),
                    )
                )
                await db.commit()

        except asyncio.TimeoutError:
            active_probes_failed = True
            logger.warning("active_probes_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "active_probes",
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            active_probes_failed = True
            aux_error_count += 1
            logger.error("active_probes_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "active_probes",
                    )
                    .values(status="failed", finished_at=datetime.now(timezone.utc), error_msg=str(exc)[:500])
                )
                await db.commit()

        # ── CanaryProbesEngine ────────────────────────────────────────────────
        canary_probes_findings = []
        canary_probes_failed = False
        try:
            from app.engines.canary_probes import CanaryProbesEngine
            from app.core.config import settings as _settings
            if _settings.CANARY_EMAIL and _offensive_allowed:
                async with AsyncSessionLocal() as db:
                    lease_check = await db.execute(
                        select(Scan.id).where(
                            Scan.id == uuid.UUID(scan_id),
                            Scan.worker_lease_id == lease_id,
                        )
                    )
                    if not lease_check.fetchone():
                        logger.warning("lease_stolen_before_canary_probes", scan_id=scan_id)
                        return
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="canary_probes",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="canary_probes", progress_pct=97)
                    )
                    await db.commit()

                canary_engine = CanaryProbesEngine()
                # Effective settings take priority: org_settings → pentest_config JSONB → global .env
                _canary_override = (
                    (_eff_settings.canary_email if _eff_settings else None)
                    or _org_pentest_cfg.get("canary_email")
                )
                if _canary_override:
                    canary_engine._canary_email_override = _canary_override
                canary_result = await asyncio.wait_for(
                    canary_engine.run_from_findings(
                        domain=target_domain,
                        mx_host=_mx_host,
                        smtp_port=_smtp_connected_port,
                    ),
                    timeout=120.0,
                )
                canary_probes_findings = canary_result.findings if canary_result.success else []

                async with AsyncSessionLocal() as db:
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.scan_id == uuid.UUID(scan_id),
                            ScanEngineRun.attempt_number == attempt_number,
                            ScanEngineRun.engine == "canary_probes",
                            sa_exists(
                                select(Scan.id).where(
                                    Scan.id == uuid.UUID(scan_id),
                                    Scan.worker_lease_id == lease_id,
                                )
                            ),
                        )
                        .values(
                            status="completed",
                            finished_at=datetime.now(timezone.utc),
                            finding_count=len(canary_probes_findings),
                        )
                    )
                    await db.commit()
            else:
                logger.info("canary_probes_skipped", scan_id=scan_id, reason="CANARY_EMAIL not set")

        except asyncio.TimeoutError:
            canary_probes_failed = True
            logger.warning("canary_probes_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "canary_probes",
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            canary_probes_failed = True
            aux_error_count += 1
            logger.error("canary_probes_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "canary_probes",
                    )
                    .values(status="failed", finished_at=datetime.now(timezone.utc), error_msg=str(exc)[:500])
                )
                await db.commit()

        # ── CredentialProbesEngine ────────────────────────────────────────────
        try:
            from app.engines.credential_probes import CredentialProbesEngine, _detect_webmail_type
            from app.core.config import settings as _settings
            # Effective settings priority: org_settings → pentest_config JSONB → global .env
            # EffectiveSettings always exists once _org_id is set, so only trust
            # it when org_settings explicitly holds a value; otherwise honour the
            # pentest-config toggle (PATCH /orgs/{id}/pentest-config) before the
            # global default.
            _cred_org_row = getattr(_eff_settings, "_org", None) if _eff_settings else None
            if _cred_org_row is not None and _cred_org_row.cred_probe_enabled is not None:
                _cred_enabled = _cred_org_row.cred_probe_enabled
            else:
                _cred_enabled = _org_pentest_cfg.get("cred_probe_enabled", _settings.CRED_PROBE_ENABLED)
            _cred_enabled = _cred_enabled and _offensive_allowed
            if _cred_enabled:
                async with AsyncSessionLocal() as db:
                    lease_check = await db.execute(
                        select(Scan.id).where(
                            Scan.id == uuid.UUID(scan_id),
                            Scan.worker_lease_id == lease_id,
                        )
                    )
                    if not lease_check.fetchone():
                        logger.warning("lease_stolen_before_cred_probes", scan_id=scan_id)
                        return
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="credential_probes",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="credential_probes", progress_pct=98)
                    )
                    await db.commit()

                _webmail_type = _detect_webmail_type(_webmail_url or "")
                cred_engine = CredentialProbesEngine()
                cred_result = await asyncio.wait_for(
                    cred_engine.run_from_findings(
                        domain=target_domain,
                        mx_host=_mx_host,
                        webmail_url=_webmail_url,
                        webmail_type=_webmail_type,
                    ),
                    timeout=300.0,
                )
                cred_probes_findings = cred_result.findings if cred_result.success else []

                async with AsyncSessionLocal() as db:
                    await db.execute(
                        update(ScanEngineRun)
                        .where(
                            ScanEngineRun.scan_id == uuid.UUID(scan_id),
                            ScanEngineRun.attempt_number == attempt_number,
                            ScanEngineRun.engine == "credential_probes",
                            sa_exists(
                                select(Scan.id).where(
                                    Scan.id == uuid.UUID(scan_id),
                                    Scan.worker_lease_id == lease_id,
                                )
                            ),
                        )
                        .values(
                            status="completed",
                            finished_at=datetime.now(timezone.utc),
                            finding_count=len(cred_probes_findings),
                        )
                    )
                    await db.commit()
            else:
                logger.info("cred_probes_skipped", scan_id=scan_id, reason="CRED_PROBE_ENABLED=false")

        except asyncio.TimeoutError:
            cred_probes_failed = True
            logger.warning("cred_probes_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "credential_probes",
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            cred_probes_failed = True
            aux_error_count += 1
            logger.error("cred_probes_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "credential_probes",
                    )
                    .values(status="failed", finished_at=datetime.now(timezone.utc), error_msg=str(exc)[:500])
                )
                await db.commit()

        # ── WebPentestEngine (Option A always-on + Option B opt-in) ─────────────
        web_pentest_failed = False
        try:
            from app.engines.web_pentest import WebPentestEngine
            async with AsyncSessionLocal() as db:
                lease_check = await db.execute(
                    select(Scan.id).where(
                        Scan.id == uuid.UUID(scan_id),
                        Scan.worker_lease_id == lease_id,
                    )
                )
                if not lease_check.fetchone():
                    logger.warning("lease_stolen_before_web_pentest", scan_id=scan_id)
                    return
                if "web_pentest" in engines_to_run:
                    run = ScanEngineRun(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(scan_id),
                        attempt_number=attempt_number,
                        engine="web_pentest",
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(run)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                        .values(current_engine="web_pentest", progress_pct=97)
                    )
                await db.commit()

            if "web_pentest" in engines_to_run:
                wp_engine = WebPentestEngine()
                if "web_active_probe_enabled" in _org_pentest_cfg:
                    wp_engine._active_probe_enabled = bool(_org_pentest_cfg["web_active_probe_enabled"])
                if not _offensive_allowed:
                    wp_engine._active_probe_enabled = False
                wp_result = await asyncio.wait_for(
                    wp_engine.run(target_domain),
                    timeout=180.0,
                )
                web_pentest_findings = wp_result.findings if wp_result.success else []

            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "web_pentest",
                        sa_exists(
                            select(Scan.id).where(
                                Scan.id == uuid.UUID(scan_id),
                                Scan.worker_lease_id == lease_id,
                            )
                        ),
                    )
                    .values(
                        status="completed",
                        finished_at=datetime.now(timezone.utc),
                        finding_count=len(web_pentest_findings),
                    )
                )
                await db.commit()

        except asyncio.TimeoutError:
            web_pentest_failed = True
            logger.warning("web_pentest_engine_timeout", scan_id=scan_id)
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "web_pentest",
                    )
                    .values(status="timeout", finished_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            web_pentest_failed = True
            aux_error_count += 1
            logger.error("web_pentest_engine_error", scan_id=scan_id, error=str(exc))
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "web_pentest",
                    )
                    .values(status="failed", finished_at=datetime.now(timezone.utc), error_msg=str(exc)[:500])
                )
                await db.commit()

        # ── RiskCorrelationEngine ─────────────────────────────────────────────
        risk_correlation_findings = []
        risk_score: float | None = None
        try:
            from app.engines.risk_correlation import RiskCorrelationEngine
            async with AsyncSessionLocal() as db:
                lease_check = await db.execute(
                    select(Scan.id).where(
                        Scan.id == uuid.UUID(scan_id),
                        Scan.worker_lease_id == lease_id,
                    )
                )
                if not lease_check.fetchone():
                    logger.warning("lease_stolen_before_risk_correlation", scan_id=scan_id)
                    return
                run = ScanEngineRun(
                    id=uuid.uuid4(),
                    scan_id=uuid.UUID(scan_id),
                    attempt_number=attempt_number,
                    engine="risk_correlation",
                    status="running",
                    started_at=datetime.now(timezone.utc),
                )
                db.add(run)
                await db.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                    .values(current_engine="risk_correlation", progress_pct=100)
                )
                await db.commit()

            prior = (
                dns_findings + smtp_findings + smtp_security_findings
                + webmail_findings + vuln_intel_findings + secrets_findings
                + web_security_findings + active_probes_findings
                + canary_probes_findings + cred_probes_findings + web_pentest_findings
            )
            corr_engine = RiskCorrelationEngine()
            corr_result = corr_engine.run(target_domain, prior)
            risk_correlation_findings = corr_result.findings
            risk_score = corr_result.risk_score

            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ScanEngineRun)
                    .where(
                        ScanEngineRun.scan_id == uuid.UUID(scan_id),
                        ScanEngineRun.attempt_number == attempt_number,
                        ScanEngineRun.engine == "risk_correlation",
                        sa_exists(
                            select(Scan.id).where(
                                Scan.id == uuid.UUID(scan_id),
                                Scan.worker_lease_id == lease_id,
                            )
                        ),
                    )
                    .values(
                        status="completed",
                        finished_at=datetime.now(timezone.utc),
                        finding_count=len(risk_correlation_findings),
                    )
                )
                await db.commit()

        except Exception as exc:
            logger.error("risk_correlation_engine_error", scan_id=scan_id, error=str(exc))

        # Final cancel checkpoint
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan.cancel_requested, Scan.status)
                .where(Scan.id == uuid.UUID(scan_id))
            )
            check = result.fetchone()
        if check and (check[0] or check[1] == ScanStatus.CANCELLED):
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                    .values(
                        status=ScanStatus.CANCELLED,
                        completed_at=datetime.now(timezone.utc),
                        error_msg="Cancelled by user",
                        current_engine=None,
                        worker_lease_id=None,
                    )
                )
                await db.commit()
            return

        # Determine final status.
        # Core engines drive FAILED/PARTIAL. Aux engine timeouts = "not applicable"
        # (domain may not have webmail, pentest surface, etc.) — not a scan failure.
        # Only real crashes (aux_error_count > 0) degrade to PARTIAL.
        both_core_failed = dns_failed and smtp_failed
        any_core_failed = dns_failed or smtp_failed
        if both_core_failed:
            final_status = ScanStatus.FAILED
        elif any_core_failed or aux_error_count > 0:
            final_status = ScanStatus.PARTIAL
        else:
            final_status = ScanStatus.COMPLETED

        all_findings = (
            dns_findings + smtp_findings + smtp_security_findings + webmail_findings
            + vuln_intel_findings + secrets_findings + web_security_findings
            + active_probes_findings + canary_probes_findings + cred_probes_findings
            + web_pentest_findings + risk_correlation_findings
        )
        # Cap at SCAN_MAX_FINDINGS_PER_RUN (guard against runaway engines)
        all_findings = all_findings[: settings.SCAN_MAX_FINDINGS_PER_RUN]

        # ── Canonical finding deduplication ───────────────────────────────────
        import hashlib
        from app.db.models.finding import CanonicalFinding

        scan_project_id: Optional[uuid.UUID] = None
        scan_org_id: Optional[uuid.UUID] = None

        async with AsyncSessionLocal() as db:
            scan_meta = await db.execute(
                select(Scan.project_id, Scan.org_id).where(Scan.id == uuid.UUID(scan_id))
            )
            row = scan_meta.fetchone()
            if row:
                scan_project_id = row[0]
                scan_org_id = row[1]

        canonical_id_map: dict = {}  # fingerprint -> canonical_finding.id

        if scan_org_id:
            now_ts = datetime.now(timezone.utc)
            async with AsyncSessionLocal() as db:
                for finding in all_findings:
                    fp_raw = (
                        f"{finding.engine}:{finding.check_id}:"
                        f"{getattr(finding, 'affected_asset', '') or ''}:"
                        f"{str(scan_project_id or scan_org_id)}"
                    )
                    fp = hashlib.sha256(fp_raw.encode()).hexdigest()

                    existing = await db.execute(
                        select(CanonicalFinding).where(
                            CanonicalFinding.fingerprint == fp,
                            CanonicalFinding.project_id == scan_project_id,
                            CanonicalFinding.org_id == scan_org_id,
                        )
                    )
                    canon = existing.scalar_one_or_none()

                    if canon:
                        canon.last_detected_at = now_ts
                        canon.observation_count += 1
                        await db.flush()
                        canonical_id_map[fp] = canon.id
                    else:
                        new_canon = CanonicalFinding(
                            id=uuid.uuid4(),
                            org_id=scan_org_id,
                            project_id=scan_project_id,
                            fingerprint=fp,
                            engine=finding.engine,
                            check_id=finding.check_id,
                            title=finding.title,
                            status="open",
                            risk_level=finding.risk_level.value,
                            first_detected_at=finding.detected_at,
                            last_detected_at=finding.detected_at,
                            observation_count=1,
                        )
                        db.add(new_canon)
                        await db.flush()
                        canonical_id_map[fp] = new_canon.id

                await db.commit()

        # ── Asset discovery feed ──────────────────────────────────────────────
        if scan_org_id:
            from app.db.models.asset import Asset
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            discovered: list[dict] = []
            # target domain is always discovered
            discovered.append({"asset_type": "domain", "value": target_domain, "metadata": {}})
            # MX hosts + SMTP endpoints from affected_asset fields
            for f in all_findings:
                val = getattr(f, "affected_asset", None)
                if not val or val == target_domain:
                    continue
                atype = "domain"
                if f.engine == "smtp_discovery":
                    atype = "smtp_endpoint" if ":" in val else "mx_record"
                elif f.engine == "webmail":
                    atype = "webmail"
                discovered.append({"asset_type": atype, "value": val, "metadata": {"engine": f.engine}})

            # Deduplicate by (type, value) before upsert
            seen: set = set()
            unique_assets: list[dict] = []
            for d in discovered:
                key = (d["asset_type"], d["value"])
                if key not in seen:
                    seen.add(key)
                    unique_assets.append(d)

            if unique_assets:
                now_ts = datetime.now(timezone.utc)
                async with AsyncSessionLocal() as db:
                    for a in unique_assets:
                        stmt = (
                            pg_insert(Asset)
                            .values(
                                id=uuid.uuid4(),
                                org_id=scan_org_id,
                                asset_type=a["asset_type"],
                                value=a["value"],
                                asset_metadata=a["metadata"],
                                first_seen_at=now_ts,
                                last_seen_at=now_ts,
                            )
                            .on_conflict_do_update(
                                constraint="uq_assets_org_type_value",
                                set_={"last_seen_at": now_ts},
                            )
                        )
                        await db.execute(stmt)
                    await db.commit()

        # ── BUG-05: guarded final write ───────────────────────────────────────
        async with AsyncSessionLocal() as db:
            # Idempotent: delete old findings for this attempt before inserting
            from sqlalchemy import delete as sa_delete
            from app.db.models.scan import FindingStatus, ScanFinding as SF
            await db.execute(sa_delete(SF).where(SF.scan_id == uuid.UUID(scan_id)))

            for finding in all_findings:
                fp_raw = (
                    f"{finding.engine}:{finding.check_id}:"
                    f"{getattr(finding, 'affected_asset', '') or ''}:"
                    f"{str(scan_project_id or scan_org_id or '')}"
                )
                fp = hashlib.sha256(fp_raw.encode()).hexdigest()
                db_finding = ScanFinding(
                    id=finding.id,
                    scan_id=uuid.UUID(scan_id),
                    engine=finding.engine,
                    check_id=finding.check_id,
                    title=finding.title,
                    description=finding.description,
                    risk_level=RiskLevel(finding.risk_level.value),
                    confidence=finding.confidence,
                    evidence=[e.model_dump(mode="json") for e in finding.evidence],
                    remediation=finding.remediation,
                    created_at=finding.detected_at,
                    status=FindingStatus.OPEN,
                    affected_asset=getattr(finding, "affected_asset", None),
                    references=getattr(finding, "references", []) or [],
                    last_seen_at=finding.detected_at,
                    fingerprint=fp,
                    canonical_finding_id=canonical_id_map.get(fp),
                )
                db.add(db_finding)

            update_result = await db.execute(
                update(Scan)
                .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                .values(
                    status=final_status,
                    completed_at=datetime.now(timezone.utc),
                    current_engine=None,
                    progress_pct=100,
                    worker_lease_id=None,
                    lease_expires_at=None,
                    risk_score=risk_score,
                )
                .returning(Scan.id)
            )
            if not update_result.fetchone():
                # Lease stolen by recovery process — abandon write
                await db.rollback()
                logger.warning("lease_stolen_on_final_write", scan_id=scan_id)
                return
            await db.commit()

        logger.info(
            "scan_completed",
            scan_id=scan_id,
            status=final_status.value,
            findings=len(all_findings),
        )

        # Compute monitoring delta if scan came from a schedule
        try:
            async with AsyncSessionLocal() as db:
                sched_result = await db.execute(
                    select(Scan.monitoring_schedule_id).where(Scan.id == uuid.UUID(scan_id))
                )
                row = sched_result.fetchone()
                sched_id = row[0] if row else None
            if sched_id:
                await compute_monitoring_delta(scan_id, str(sched_id))
        except Exception as delta_exc:
            logger.error("monitoring_delta_error", scan_id=scan_id, error=str(delta_exc))

        # Webhook dispatch (non-blocking, best-effort)
        try:
            if scan_org_id:
                from app.worker.webhook_dispatch import dispatch_webhooks
                from app.db.models.webhook import WebhookEvent

                async def _wh_send(coro) -> None:
                    # Already inside the scan's running loop: await directly
                    # (asyncio.run() would raise). Bounded so a slow tenant
                    # endpoint cannot hold the scan finalisation hostage.
                    try:
                        await asyncio.wait_for(coro, timeout=30)
                    except Exception as _send_err:
                        logger.warning(
                            "webhook_dispatch_error",
                            scan_id=scan_id,
                            error_type=type(_send_err).__name__,
                        )

                _wh_event = (
                    WebhookEvent.SCAN_COMPLETED
                    if final_status == ScanStatus.COMPLETED
                    else WebhookEvent.SCAN_FAILED
                )
                _wh_payload = {
                    "scan_id": str(scan_id),
                    "domain": target_domain,
                    "status": final_status.value,
                    "risk_score": risk_score,
                    "finding_count": len(all_findings),
                }
                await _wh_send(dispatch_webhooks(scan_org_id, _wh_event, _wh_payload))

                _critical = [
                    f for f in all_findings
                    if getattr(f, "risk_level", None) is not None
                    and str(f.risk_level).lower() in ("critical", "risklevel.critical")
                ]
                _high = [
                    f for f in all_findings
                    if getattr(f, "risk_level", None) is not None
                    and str(f.risk_level).lower() in ("high", "risklevel.high")
                ]
                if _critical:
                    await _wh_send(dispatch_webhooks(
                        scan_org_id,
                        WebhookEvent.FINDING_CRITICAL,
                        {
                            "scan_id": str(scan_id),
                            "domain": target_domain,
                            "critical_count": len(_critical),
                            "findings": [
                                {
                                    "check_id": getattr(f, "check_id", ""),
                                    "title": getattr(f, "title", ""),
                                }
                                for f in _critical[:5]
                            ],
                        },
                    ))
                if _high:
                    await _wh_send(dispatch_webhooks(
                        scan_org_id,
                        WebhookEvent.FINDING_HIGH,
                        {
                            "scan_id": str(scan_id),
                            "domain": target_domain,
                            "high_count": len(_high),
                        },
                    ))
        except Exception as _wh_err:
            logger.warning("webhook_dispatch_error", scan_id=scan_id, error=str(_wh_err))

    except SoftTimeLimitExceeded:
        logger.warning("scan_soft_time_limit", scan_id=scan_id)
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(ScanEngineRun)
                .where(
                    ScanEngineRun.scan_id == uuid.UUID(scan_id),
                    ScanEngineRun.status == "running",
                )
                .values(status="timeout", finished_at=datetime.now(timezone.utc))
            )
            await db.commit()
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(Scan)
                .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                .values(
                    status=ScanStatus.PARTIAL,
                    completed_at=datetime.now(timezone.utc),
                    error_msg="Scan timed out",
                    current_engine=None,
                    worker_lease_id=None,
                )
            )
            await db.commit()
        raise

    except Exception as exc:
        logger.error("scan_task_unhandled", scan_id=scan_id, error=str(exc))
        # BUG-03: retry resets to QUEUED; FAILED only on max_retries exhausted
        retries_left = task.max_retries - task.request.retries
        if retries_left > 0:
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                    .values(
                        status=ScanStatus.QUEUED,
                        started_at=None,
                        current_engine=None,
                        progress_pct=0,
                        worker_lease_id=None,
                        lease_expires_at=None,
                    )
                )
                await db.commit()
        else:
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id), Scan.worker_lease_id == lease_id)
                    .values(
                        status=ScanStatus.FAILED,
                        completed_at=datetime.now(timezone.utc),
                        error_msg=f"Unexpected error: {type(exc).__name__}",
                        current_engine=None,
                        worker_lease_id=None,
                    )
                )
                await db.commit()
        # A failure to schedule the retry is handled by scan_task (marks FAILED)
        raise task.retry(exc=exc)

    finally:
        heartbeat_stop.set()
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except (asyncio.CancelledError, Exception):
            pass


# ── Stall recovery ────────────────────────────────────────────────────────────


async def _recover_stalled() -> None:
    from app.db.session import AsyncSessionLocal
    from app.db.models.scan import Scan, ScanOutbox, ScanStatus
    from sqlalchemy import select, update, text, or_, and_
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    stall_threshold = datetime.now(timezone.utc) - timedelta(
        seconds=settings.SCAN_STALL_TIMEOUT_SECONDS
    )

    async with AsyncSessionLocal() as db:
        # BUG-04: SELECT FOR UPDATE SKIP LOCKED prevents double-dispatch by concurrent beats
        # F-03 FIX: use heartbeat_at < stall_threshold (not lease_expires_at) so that
        # SCAN_STALL_TIMEOUT_SECONDS is the authoritative stall window; also handle
        # RUNNING scans that never sent a heartbeat (started_at fallback).
        result = await db.execute(
            select(Scan)
            .where(
                Scan.status == ScanStatus.RUNNING,
                or_(
                    Scan.heartbeat_at < stall_threshold,
                    and_(
                        Scan.heartbeat_at == None,  # noqa: E711
                        Scan.started_at != None,  # noqa: E711
                        Scan.started_at < stall_threshold,
                    ),
                ),
            )
            .with_for_update(skip_locked=True)
        )
        stalled = list(result.scalars().all())

        for scan in stalled:
            logger.warning("recovering_stalled_scan", scan_id=str(scan.id))
            scan.status = ScanStatus.QUEUED
            scan.started_at = None
            scan.current_engine = None
            scan.progress_pct = 0
            scan.worker_lease_id = None
            scan.lease_expires_at = None

        if stalled:
            await db.flush()

            # BUG-01: upsert instead of INSERT — avoids IntegrityError on UNIQUE(scan_id)
            # The recovery path must enforce SCAN_MAX_TOTAL_ATTEMPTS itself: the
            # entry is published right below, so the unpublished-outbox check
            # further down never sees it, and each redispatch is a fresh Celery
            # task (max_retries does not apply).
            to_dispatch = []
            for scan in stalled:
                attempt_row = await db.execute(
                    text(
                        "INSERT INTO scan_outbox (id, scan_id, published, created_at, attempt_count) "
                        "VALUES (:id, :scan_id, false, now(), 0) "
                        "ON CONFLICT (scan_id) DO UPDATE "
                        "SET published = false, published_at = NULL, "
                        "    celery_task_id = NULL, "
                        "    attempt_count = scan_outbox.attempt_count + 1 "
                        "RETURNING attempt_count"
                    ),
                    {"id": str(uuid.uuid4()), "scan_id": str(scan.id)},
                )
                attempt_count = attempt_row.scalar_one()
                if attempt_count >= settings.SCAN_MAX_TOTAL_ATTEMPTS:
                    logger.error(
                        "scan_max_attempts_exceeded",
                        scan_id=str(scan.id),
                        attempt_count=attempt_count,
                    )
                    scan.status = ScanStatus.FAILED
                    scan.error_msg = (
                        f"Max attempts ({settings.SCAN_MAX_TOTAL_ATTEMPTS}) exceeded"
                    )
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.execute(
                        text(
                            "UPDATE scan_outbox SET published = true, published_at = now() "
                            "WHERE scan_id = :scan_id"
                        ),
                        {"scan_id": str(scan.id)},
                    )
                else:
                    to_dispatch.append(scan)

            await db.commit()
            for scan in to_dispatch:
                try:
                    task = scan_task.delay(str(scan.id))
                    await db.execute(
                        text(
                            "UPDATE scan_outbox SET published = true, published_at = now(), "
                            "celery_task_id = :task_id WHERE scan_id = :scan_id"
                        ),
                        {"task_id": task.id, "scan_id": str(scan.id)},
                    )
                    await db.commit()
                except Exception as exc:
                    logger.error("recovery_dispatch_failed", scan_id=str(scan.id), error=str(exc))

        # Re-dispatch unpublished outbox entries (failed initial dispatch)
        result = await db.execute(
            select(ScanOutbox)
            .where(ScanOutbox.published == False)  # noqa: E712
            .with_for_update(skip_locked=True)
        )
        unpublished = list(result.scalars().all())

        for entry in unpublished:
            if entry.attempt_count >= settings.SCAN_MAX_TOTAL_ATTEMPTS:
                logger.error(
                    "scan_max_attempts_exceeded",
                    scan_id=str(entry.scan_id),
                    attempt_count=entry.attempt_count,
                )
                await db.execute(
                    update(Scan)
                    .where(Scan.id == entry.scan_id)
                    .values(
                        status=ScanStatus.FAILED,
                        error_msg=f"Max dispatch attempts ({settings.SCAN_MAX_TOTAL_ATTEMPTS}) exceeded",
                        completed_at=datetime.now(timezone.utc),
                    )
                )
                entry.published = True
                entry.published_at = datetime.now(timezone.utc)
                continue
            logger.info("republishing_outbox_entry", scan_id=str(entry.scan_id))
            try:
                task_result = scan_task.delay(str(entry.scan_id))
                entry.published = True
                entry.celery_task_id = task_result.id
                entry.published_at = datetime.now(timezone.utc)
            except Exception as exc:
                logger.error("outbox_dispatch_failed", scan_id=str(entry.scan_id), error=str(exc))

        if unpublished:
            await db.flush()
            await db.commit()


# ── Continuous monitoring ─────────────────────────────────────────────────────


@celery_app.task(name="mailox.check_monitoring_schedules")
def check_monitoring_schedules() -> None:
    _run_async(_check_monitoring_schedules())


async def _check_monitoring_schedules() -> None:
    """
    Beat task: pick up enabled monitoring schedules whose next_run_at <= now,
    create a scan for each, advance next_run_at.
    Uses SELECT FOR UPDATE SKIP LOCKED so concurrent beat workers don't double-dispatch.
    """
    from app.db.session import AsyncSessionLocal
    from app.db.models.monitoring import MonitoringSchedule
    from app.db.models.scan import Scan, ScanStatus, ScanOutbox
    from app.db.models.project import Project
    from sqlalchemy import select, update
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(MonitoringSchedule)
            .where(
                MonitoringSchedule.enabled == True,  # noqa: E712
                MonitoringSchedule.next_run_at <= now,
                MonitoringSchedule.next_run_at != None,  # noqa: E711
            )
            .with_for_update(skip_locked=True)
        )
        due = list(result.scalars().all())

        for schedule in due:
            try:
                # Fetch project to get org_id and target domain
                proj_result = await db.execute(
                    select(Project).where(Project.id == schedule.project_id)
                )
                project = proj_result.scalar_one_or_none()
                if not project:
                    logger.warning("monitoring_project_not_found", schedule_id=str(schedule.id))
                    continue

                # Determine target domain from project scope or last scan
                target_domain = await _resolve_monitoring_target(db, schedule, project)
                if not target_domain:
                    logger.warning(
                        "monitoring_no_target",
                        schedule_id=str(schedule.id),
                        project_id=str(project.id),
                    )
                    continue

                # Create scan
                new_scan = Scan(
                    id=uuid.uuid4(),
                    org_id=project.org_id,
                    project_id=schedule.project_id,
                    target_domain=target_domain,
                    status=ScanStatus.QUEUED,
                    created_at=now,
                    monitoring_schedule_id=schedule.id,
                )
                db.add(new_scan)
                await db.flush()

                # Outbox entry
                await db.execute(
                    pg_insert(ScanOutbox)
                    .values(
                        id=uuid.uuid4(),
                        scan_id=new_scan.id,
                        published=False,
                        created_at=now,
                        attempt_count=0,
                    )
                    .on_conflict_do_nothing(index_elements=["scan_id"])
                )

                # Advance schedule
                next_run = _compute_cron_next(schedule.cron_expression, now)
                schedule.last_run_at = now
                schedule.last_scan_id = new_scan.id
                schedule.next_run_at = next_run

                logger.info(
                    "monitoring_scan_queued",
                    schedule_id=str(schedule.id),
                    scan_id=str(new_scan.id),
                    next_run_at=next_run.isoformat(),
                )

            except Exception as exc:
                logger.error(
                    "monitoring_dispatch_error",
                    schedule_id=str(schedule.id),
                    error=str(exc),
                )

        if due:
            await db.commit()


def _compute_cron_next(expr: str, after: datetime) -> datetime:
    """Compute next run time after `after` for a cron expression."""
    try:
        from croniter import croniter
        it = croniter(expr, after)
        return it.get_next(datetime)
    except Exception:
        # Fallback: 24 hours
        from datetime import timedelta
        return after + timedelta(hours=24)


async def _resolve_monitoring_target(db, schedule, project) -> Optional[str]:
    """
    Find the target domain for a monitoring scan.
    Priority: last scan for this schedule → first scope entry → None.
    """
    from app.db.models.scan import Scan
    from sqlalchemy import select

    # Last scan from this schedule
    if schedule.last_scan_id:
        result = await db.execute(
            select(Scan.target_domain).where(Scan.id == schedule.last_scan_id)
        )
        row = result.fetchone()
        if row:
            return row[0]

    # First scan for this project (any)
    result = await db.execute(
        select(Scan.target_domain)
        .where(Scan.project_id == schedule.project_id)
        .order_by(Scan.created_at.asc())
        .limit(1)
    )
    row = result.fetchone()
    if row:
        return row[0]

    return None


# ── CVE Intelligence sync tasks ───────────────────────────────────────────────


@celery_app.task(name="intel.sync_nvd", bind=True, max_retries=2)
def sync_nvd_task(self) -> dict:
    async def _run():
        from app.db.session import AsyncSessionLocal
        from app.services.intel.nvd_service import NVDIngestionService
        async with AsyncSessionLocal() as db:
            service = NVDIngestionService()
            result = await service.sync(db)
            await db.commit()
            return {"added": result.added, "updated": result.updated, "skipped": result.skipped, "failed": result.failed}
    try:
        return _run_async(_run())
    except Exception as exc:
        logger.error("sync_nvd_failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300)


@celery_app.task(name="intel.sync_cisa_kev", bind=True, max_retries=2)
def sync_cisa_kev_task(self) -> dict:
    async def _run():
        from app.db.session import AsyncSessionLocal
        from app.services.intel.cisa_kev_service import CISAKEVService
        async with AsyncSessionLocal() as db:
            service = CISAKEVService()
            result = await service.sync(db)
            await db.commit()
            return {"added": result.added, "updated": result.updated, "skipped": result.skipped, "failed": result.failed}
    try:
        return _run_async(_run())
    except Exception as exc:
        logger.error("sync_cisa_kev_failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300)


@celery_app.task(name="intel.sync_osv", bind=True, max_retries=2)
def sync_osv_task(self) -> dict:
    async def _run():
        from app.db.session import AsyncSessionLocal
        from app.services.intel.osv_service import OSVIngestionService
        async with AsyncSessionLocal() as db:
            service = OSVIngestionService()
            result = await service.sync(db)
            await db.commit()
            return {"added": result.added, "updated": result.updated, "skipped": result.skipped, "failed": result.failed}
    try:
        return _run_async(_run())
    except Exception as exc:
        logger.error("sync_osv_failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300)


@celery_app.task(name="intel.sync_all", bind=True)
def sync_all_intel_task(self) -> dict:
    """Run NVD → CISA KEV → OSV sequentially."""
    results = {}
    for task_fn, source in [
        (sync_nvd_task, "nvd"),
        (sync_cisa_kev_task, "cisa_kev"),
        (sync_osv_task, "osv"),
    ]:
        try:
            results[source] = task_fn()
        except Exception as exc:
            logger.error("sync_all_source_failed", source=source, error=str(exc))
            results[source] = {"error": str(exc)}
    return results


async def compute_monitoring_delta(scan_id: str, schedule_id: str) -> None:
    """
    Compare current scan's canonical findings against previous scan's findings.
    Inserts a MonitoringDelta row. Called after scan finalization.
    """
    from app.db.session import AsyncSessionLocal
    from app.db.models.monitoring import MonitoringSchedule, MonitoringDelta
    from app.db.models.scan import Scan
    from app.db.models.finding import CanonicalFinding
    from sqlalchemy import select, func

    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as db:
        # Get current and previous scan
        sched_result = await db.execute(
            select(MonitoringSchedule).where(MonitoringSchedule.id == uuid.UUID(schedule_id))
        )
        schedule = sched_result.scalar_one_or_none()
        if not schedule:
            return

        previous_scan_id = schedule.last_scan_id
        current_scan_id_uuid = uuid.UUID(scan_id)

        # Fingerprints from current scan (via CanonicalFinding last_detected via scan findings)
        # We compare canonical findings by looking at which ones were updated/seen in each scan
        current_fp_result = await db.execute(
            select(CanonicalFinding.fingerprint, CanonicalFinding.risk_level)
            .where(CanonicalFinding.project_id == schedule.project_id)
            .where(
                CanonicalFinding.last_detected_at >= (
                    select(Scan.created_at).where(Scan.id == current_scan_id_uuid).scalar_subquery()
                )
            )
        )
        current_findings = {row.fingerprint: row.risk_level for row in current_fp_result}

        previous_findings: dict = {}
        if previous_scan_id:
            prev_fp_result = await db.execute(
                select(CanonicalFinding.fingerprint, CanonicalFinding.risk_level)
                .where(CanonicalFinding.project_id == schedule.project_id)
                .where(
                    CanonicalFinding.last_detected_at >= (
                        select(Scan.created_at).where(Scan.id == previous_scan_id).scalar_subquery()
                    )
                )
                .where(
                    CanonicalFinding.last_detected_at < (
                        select(Scan.created_at).where(Scan.id == current_scan_id_uuid).scalar_subquery()
                    )
                )
            )
            previous_findings = {row.fingerprint: row.risk_level for row in prev_fp_result}

        current_fps = set(current_findings.keys())
        previous_fps = set(previous_findings.keys())

        new_count = len(current_fps - previous_fps)
        persistent_count = len(current_fps & previous_fps)
        resolved_count = len(previous_fps - current_fps)
        severity_changed_count = sum(
            1 for fp in (current_fps & previous_fps)
            if current_findings.get(fp) != previous_findings.get(fp)
        )

        delta = MonitoringDelta(
            id=uuid.uuid4(),
            schedule_id=uuid.UUID(schedule_id),
            scan_id=current_scan_id_uuid,
            previous_scan_id=previous_scan_id,
            new_findings=new_count,
            persistent_findings=persistent_count,
            resolved_findings=resolved_count,
            severity_changed=severity_changed_count,
            computed_at=now,
        )
        db.add(delta)
        await db.commit()

        logger.info(
            "monitoring_delta_computed",
            scan_id=scan_id,
            schedule_id=schedule_id,
            new=new_count,
            persistent=persistent_count,
            resolved=resolved_count,
            severity_changed=severity_changed_count,
        )


# ── Scheduled rescans ─────────────────────────────────────────────────────────


@celery_app.task(name="mailox.run_scheduled_scans")
def run_scheduled_scans() -> None:
    """Check scan schedules and launch due scans. Called by Celery beat every hour."""

    async def _check() -> None:
        from app.db.session import AsyncSessionLocal
        from app.db.models.scan_schedule import ScanSchedule, ScheduleInterval
        from app.db.models.scan import Scan, ScanOutbox, ScanStatus
        from app.worker.tasks import scan_task  # local import — avoids circular at module load
        from sqlalchemy import select

        async with AsyncSessionLocal() as db:
            now = datetime.now(timezone.utc)
            result = await db.execute(
                select(ScanSchedule).where(
                    ScanSchedule.enabled == True,
                    ScanSchedule.next_run_at <= now,
                )
            )
            schedules = result.scalars().all()

            for sched in schedules:
                try:
                    scan_id = uuid.uuid4()
                    scan = Scan(
                        id=scan_id,
                        org_id=sched.org_id,
                        target_domain=sched.domain,
                        status=ScanStatus.QUEUED,
                        created_by=sched.created_by,
                        created_at=now,
                    )
                    db.add(scan)
                    await db.flush()

                    outbox = ScanOutbox(scan_id=scan_id)
                    db.add(outbox)
                    await db.flush()
                    await db.commit()

                    task = scan_task.delay(str(scan_id))
                    outbox.celery_task_id = task.id
                    outbox.published = True
                    outbox.published_at = now
                    await db.flush()

                    logger.info(
                        "scheduled_scan_launched",
                        domain=sched.domain,
                        schedule_id=str(sched.id),
                        scan_id=str(scan_id),
                    )
                except Exception as exc:
                    logger.error(
                        "scheduled_scan_failed",
                        domain=sched.domain,
                        schedule_id=str(sched.id),
                        error=str(exc),
                    )
                    # Roll back so we can still update next_run_at
                    await db.rollback()

                # Advance next_run_at regardless of dispatch outcome
                try:
                    if sched.interval == ScheduleInterval.DAILY:
                        sched.next_run_at = now + timedelta(days=1)
                    elif sched.interval == ScheduleInterval.WEEKLY:
                        sched.next_run_at = now + timedelta(weeks=1)
                    else:  # MONTHLY
                        sched.next_run_at = now + timedelta(days=30)
                    sched.last_run_at = now
                    await db.merge(sched)
                    await db.commit()
                except Exception as exc:
                    logger.error(
                        "scheduled_scan_next_run_update_failed",
                        schedule_id=str(sched.id),
                        error=str(exc),
                    )

    _run_async(_check())
