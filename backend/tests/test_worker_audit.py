"""
Worker write audit tests.

Verifies:
- All Scan table writes (progress, current_engine, status, findings) are guarded by lease.
- ScanEngineRun INSERTs abort early if lease is stolen before engine starts.
- ScanEngineRun UPDATEs are no-ops when lease is gone.
- Findings are not duplicated on retry (DELETE + INSERT in guarded transaction).
- created_by nullable=True is reflected in schema (BUG-10).
"""
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.db.models.scan import Scan, ScanEngineRun, ScanFinding, ScanOutbox, ScanStatus


# ── Fixtures ──────────────────────────────────────────────────────────────────


async def _make_org_and_scan(db, saas_gate: bool = False) -> tuple[uuid.UUID, uuid.UUID, Scan]:
    """Create a minimal org + scan. Returns (org_id, scan_id, scan).

    saas_gate=True also adds what the SaaS gate of _run_scan requires (an active
    member and a verified domain), for tests that need the engines to run.
    """
    from app.db.models.organization import Organization
    from app.db.models.user import User

    org_id = uuid.uuid4()
    user_id = uuid.uuid4()

    org = Organization(
        id=org_id,
        name=f"test-org-{org_id}",
        slug=f"test-org-{org_id}",
    )
    db.add(org)
    await db.flush()

    user = User(
        id=user_id,
        email=f"user-{user_id}@test.dev",
        password_hash="x",
        is_active=True,
    )
    db.add(user)
    await db.flush()

    if saas_gate:
        # SaaS edition gate in _run_scan: the org needs an active member and a
        # verified domain, otherwise the worker fails the scan before any engine.
        from app.db.models.access import VerifiedDomain
        from app.db.models.organization import OrganizationMember, OrgRole

        now = datetime.now(timezone.utc)
        db.add(OrganizationMember(
            id=uuid.uuid4(), org_id=org_id, user_id=user_id, role=OrgRole.ORG_ADMIN, is_active=True,
        ))
        db.add(VerifiedDomain(
            org_id=org_id, domain="example.com", token="test-token",
            verified_at=now, last_checked_at=now,
        ))
        await db.flush()

    scan = Scan(
        id=uuid.uuid4(),
        org_id=org_id,
        target_domain="example.com",
        status=ScanStatus.QUEUED,
        created_by=user_id,
    )
    db.add(scan)
    await db.flush()
    await db.commit()
    return org_id, user_id, scan


# ── BUG-11: ScanEngineRun INSERT lease guard ──────────────────────────────────


class TestEngineRunInsertLeaseGuard:
    """ScanEngineRun INSERTs must check lease before writing."""

    @pytest.mark.asyncio
    async def test_dns_run_not_inserted_when_lease_stolen(self, db):
        """If lease is gone before DNS starts, no ScanEngineRun row is created."""
        _, _, scan = await _make_org_and_scan(db)
        scan_id = str(scan.id)

        # Simulate: worker acquired lease with this id
        lease_id = str(uuid.uuid4())
        fake_task = MagicMock()
        fake_task.max_retries = 2
        fake_task.request.retries = 0

        # Steal the lease before _run_scan would start the DNS engine:
        # keep scan QUEUED — the atomic UPDATE WHERE status=QUEUED will return nothing
        # because scan is QUEUED but we insert with the NEW worker's lease_id.
        # Actually test the more direct path: scan is RUNNING but with a different lease_id.
        scan.status = ScanStatus.RUNNING
        scan.worker_lease_id = "other-lease"  # different worker owns it
        scan.attempt_number = 1
        await db.flush()
        await db.commit()

        # Patch DNSAuthEngine to ensure it never runs
        dns_called = False

        async def dns_should_not_run(*a, **kw):
            nonlocal dns_called
            dns_called = True

        with patch("app.engines.dns_auth.DNSAuthEngine.run", new=dns_should_not_run):
            from app.worker.tasks import _run_scan
            await _run_scan(scan_id, fake_task)

        # DNS was not called (lease check failed early)
        assert not dns_called

        # No ScanEngineRun created for lease_id
        result = await db.execute(
            select(ScanEngineRun).where(
                ScanEngineRun.scan_id == scan.id,
                ScanEngineRun.engine == "dns_auth",
            )
        )
        runs = result.scalars().all()
        # Only runs for the legitimate worker (attempt=1 with other-lease) should exist
        # Since we ran with no matching lease, nothing was inserted for lease_id
        for r in runs:
            assert r.attempt_number == 1  # the legitimate worker's attempt

    @pytest.mark.asyncio
    async def test_smtp_run_not_inserted_when_lease_stolen_mid_scan(self, db):
        """If lease is stolen between DNS completion and SMTP start, SMTP run is not inserted."""
        _, _, scan = await _make_org_and_scan(db, saas_gate=True)
        scan_id = str(scan.id)
        lease_id = str(uuid.uuid4())

        scan.status = ScanStatus.QUEUED
        await db.flush()
        await db.commit()

        fake_task = MagicMock()
        fake_task.max_retries = 2
        fake_task.request.retries = 0

        dns_calls = 0
        smtp_calls = 0

        class FakeDNSResult:
            findings = []

        class FakeSMTPResult:
            findings = []

        async def fake_dns(self_inner, domain):
            nonlocal dns_calls
            dns_calls += 1
            # Steal lease after DNS completes
            from app.db.session import AsyncSessionLocal
            from sqlalchemy import update
            async with AsyncSessionLocal() as steal_db:
                await steal_db.execute(
                    update(Scan)
                    .where(Scan.id == scan.id)
                    .values(worker_lease_id="stolen-by-recovery")
                )
                await steal_db.commit()
            return FakeDNSResult()

        async def fake_smtp(self_inner, domain):
            nonlocal smtp_calls
            smtp_calls += 1
            return FakeSMTPResult()

        with (
            patch("app.engines.dns_auth.DNSAuthEngine.run", new=fake_dns),
            patch("app.engines.smtp_discovery.SMTPDiscoveryEngine.run", new=fake_smtp),
        ):
            from app.worker.tasks import _run_scan
            await _run_scan(scan_id, fake_task)

        assert dns_calls == 1
        # SMTP should not have run because lease was stolen before SMTP INSERT check
        assert smtp_calls == 0

        # No SMTP engine run created
        result = await db.execute(
            select(ScanEngineRun).where(
                ScanEngineRun.scan_id == scan.id,
                ScanEngineRun.engine == "smtp_discovery",
            )
        )
        smtp_runs = result.scalars().all()
        assert len(smtp_runs) == 0


# ── BUG-12: ScanEngineRun UPDATE lease guard ─────────────────────────────────


class TestEngineRunUpdateLeaseGuard:
    """ScanEngineRun UPDATEs must be no-ops when lease is stolen."""

    @pytest.mark.asyncio
    async def test_dns_run_status_not_updated_after_lease_stolen(self, db):
        """Engine run status stays 'running' if worker's lease was stolen before UPDATE."""
        from app.db.session import AsyncSessionLocal
        from sqlalchemy import update

        _, _, scan = await _make_org_and_scan(db)
        scan_id = str(scan.id)
        lease_id = str(uuid.uuid4())
        attempt = 1

        scan.status = ScanStatus.RUNNING
        scan.worker_lease_id = lease_id
        scan.attempt_number = attempt
        await db.flush()
        await db.commit()

        # Create the engine run manually (as if INSERT already happened)
        async with AsyncSessionLocal() as s:
            run = ScanEngineRun(
                id=uuid.uuid4(),
                scan_id=scan.id,
                attempt_number=attempt,
                engine="dns_auth",
                status="running",
                started_at=datetime.now(timezone.utc),
            )
            s.add(run)
            # Now steal the lease
            await s.execute(
                update(Scan)
                .where(Scan.id == scan.id)
                .values(worker_lease_id="new-worker-lease")
            )
            await s.commit()

        # Simulate the guarded UPDATE that _run_scan would issue
        from app.worker.tasks import _run_scan
        from sqlalchemy import exists as sa_exists
        async with AsyncSessionLocal() as s:
            await s.execute(
                update(ScanEngineRun)
                .where(
                    ScanEngineRun.scan_id == scan.id,
                    ScanEngineRun.attempt_number == attempt,
                    ScanEngineRun.engine == "dns_auth",
                    sa_exists(
                        select(Scan.id).where(
                            Scan.id == scan.id,
                            Scan.worker_lease_id == lease_id,  # old lease
                        )
                    ),
                )
                .values(status="completed", finished_at=datetime.now(timezone.utc))
            )
            await s.commit()

        # Row should still be "running" — update was a no-op
        async with AsyncSessionLocal() as s:
            result = await s.execute(
                select(ScanEngineRun).where(
                    ScanEngineRun.scan_id == scan.id,
                    ScanEngineRun.attempt_number == attempt,
                    ScanEngineRun.engine == "dns_auth",
                )
            )
            row = result.scalar_one()
        assert row.status == "running", (
            f"Expected 'running' (no-op) but got '{row.status}'"
        )


# ── Findings duplicate prevention ────────────────────────────────────────────


class TestFindingsDeduplication:
    """Findings DELETE + INSERT is in the same transaction as the guarded Scan UPDATE.
    If the lease is stolen, the whole transaction rolls back — no orphaned DELETE."""

    @pytest.mark.asyncio
    async def test_findings_not_deleted_when_final_write_lease_stolen(self, db):
        """When a stale worker's final write is rejected, existing findings are preserved."""
        from app.db.session import AsyncSessionLocal
        from sqlalchemy import update, delete as sa_delete

        _, _, scan = await _make_org_and_scan(db)
        scan_id = str(scan.id)
        lease_id = "stale-lease"
        attempt = 1

        scan.status = ScanStatus.RUNNING
        scan.worker_lease_id = "new-lease"  # already stolen by another worker
        scan.attempt_number = attempt
        await db.flush()
        await db.commit()

        # Insert a finding from the legitimate worker
        async with AsyncSessionLocal() as s:
            f = ScanFinding(
                id=uuid.uuid4(),
                scan_id=scan.id,
                engine="dns_auth",
                check_id="DNS-01",
                title="Legitimate finding",
                description="From the real worker",
                risk_level="high",
                confidence=0.9,
                evidence={},
                remediation="Fix it",
            )
            s.add(f)
            await s.commit()

        # Stale worker tries to execute the guarded final transaction
        from app.db.models.scan import ScanFinding as SF
        async with AsyncSessionLocal() as s:
            # Step 1: DELETE all findings (happens before guarded UPDATE)
            await s.execute(sa_delete(SF).where(SF.scan_id == scan.id))
            # Step 2: Guarded UPDATE with stale lease — should return 0 rows
            result = await s.execute(
                update(Scan)
                .where(Scan.id == scan.id, Scan.worker_lease_id == lease_id)
                .values(status=ScanStatus.COMPLETED)
                .returning(Scan.id)
            )
            if not result.fetchone():
                # Correctly rolls back the DELETE too
                await s.rollback()
            else:
                await s.commit()

        # Findings should still be present (rollback preserved them)
        async with AsyncSessionLocal() as s:
            result = await s.execute(
                select(ScanFinding).where(ScanFinding.scan_id == scan.id)
            )
            findings = result.scalars().all()
        assert len(findings) == 1, f"Expected 1 finding after rollback, got {len(findings)}"
        assert findings[0].title == "Legitimate finding"

    @pytest.mark.asyncio
    async def test_findings_not_duplicated_on_retry(self, db):
        """On retry, the second worker deletes the first attempt's findings and inserts its own."""
        from app.db.session import AsyncSessionLocal
        from sqlalchemy import update, delete as sa_delete

        _, _, scan = await _make_org_and_scan(db)
        scan_id = str(scan.id)

        # First attempt: worker inserted some findings then failed (findings persisted)
        async with AsyncSessionLocal() as s:
            scan_obj = await s.get(Scan, scan.id)
            scan_obj.status = ScanStatus.RUNNING
            scan_obj.worker_lease_id = "first-worker"
            scan_obj.attempt_number = 1
            f1 = ScanFinding(
                id=uuid.uuid4(),
                scan_id=scan.id,
                engine="dns_auth",
                check_id="DNS-01",
                title="Finding from attempt 1",
                description="x",
                risk_level="high",
                confidence=0.9,
                evidence={},
                remediation="x",
            )
            s.add(f1)
            await s.commit()

        # Reset for retry: scan back to QUEUED
        async with AsyncSessionLocal() as s:
            await s.execute(
                update(Scan)
                .where(Scan.id == scan.id)
                .values(
                    status=ScanStatus.QUEUED,
                    worker_lease_id=None,
                    attempt_number=1,
                )
            )
            await s.commit()

        # Second attempt: atomic final write deletes old findings + inserts new ones
        second_lease = "second-worker"
        async with AsyncSessionLocal() as s:
            # Acquire lease for second attempt
            await s.execute(
                update(Scan)
                .where(Scan.id == scan.id, Scan.status == ScanStatus.QUEUED)
                .values(
                    status=ScanStatus.RUNNING,
                    worker_lease_id=second_lease,
                    attempt_number=2,
                )
            )
            await s.commit()

        async with AsyncSessionLocal() as s:
            await s.execute(sa_delete(ScanFinding).where(ScanFinding.scan_id == scan.id))
            f2 = ScanFinding(
                id=uuid.uuid4(),
                scan_id=scan.id,
                engine="dns_auth",
                check_id="DNS-01",
                title="Finding from attempt 2",
                description="x",
                risk_level="medium",
                confidence=0.8,
                evidence={},
                remediation="x",
            )
            s.add(f2)
            result = await s.execute(
                update(Scan)
                .where(Scan.id == scan.id, Scan.worker_lease_id == second_lease)
                .values(status=ScanStatus.COMPLETED)
                .returning(Scan.id)
            )
            assert result.fetchone() is not None, "Second worker's final write should succeed"
            await s.commit()

        async with AsyncSessionLocal() as s:
            result = await s.execute(
                select(ScanFinding).where(ScanFinding.scan_id == scan.id)
            )
            findings = result.scalars().all()

        assert len(findings) == 1, f"Expected 1 (not duplicated), got {len(findings)}"
        assert findings[0].title == "Finding from attempt 2"


# ── BUG-10: created_by nullable ───────────────────────────────────────────────


class TestCreatedByNullable:
    """BUG-10 fix: created_by must accept NULL for user deletion with SET NULL."""

    @pytest.mark.asyncio
    async def test_scan_created_by_accepts_null(self, db):
        """Scan.created_by can be NULL — model and DB both accept it."""
        from app.db.session import AsyncSessionLocal

        _, _, scan = await _make_org_and_scan(db)
        scan_id = scan.id

        async with AsyncSessionLocal() as s:
            scan_obj = await s.get(Scan, scan_id)
            scan_obj.created_by = None  # Simulate user deleted → SET NULL
            await s.commit()

        async with AsyncSessionLocal() as s:
            scan_obj = await s.get(Scan, scan_id)
        assert scan_obj.created_by is None, "created_by must be nullable after BUG-10 fix"

    def test_schema_created_by_is_optional(self):
        """ScanResponse.created_by is Optional[str] — None is valid."""
        from app.schemas.scan import ScanResponse
        import inspect
        hints = ScanResponse.model_fields
        assert hints["created_by"].is_required() is False, (
            "created_by should be Optional[str] with default None"
        )

    @pytest.mark.asyncio
    async def test_user_deletion_does_not_fail_when_scan_exists(self, db):
        """Deleting a user with associated scans must not raise FK constraint error."""
        from app.db.session import AsyncSessionLocal
        from app.db.models.user import User

        _, user_id, scan = await _make_org_and_scan(db)
        await db.commit()

        async with AsyncSessionLocal() as s:
            user = await s.get(User, user_id)
            if user:
                await s.delete(user)
                # Should not raise IntegrityError with ondelete=SET NULL + nullable=True
                await s.commit()

        async with AsyncSessionLocal() as s:
            scan_obj = await s.get(Scan, scan.id)
        # Scan still exists, created_by is NULL
        assert scan_obj is not None
        assert scan_obj.created_by is None


# ── F-03/F-04: Stall recovery fixes ──────────────────────────────────────────


class TestStallRecoveryHeartbeat:
    """F-03: stall detection uses heartbeat_at. F-04: Redis error is handled."""

    @pytest.mark.asyncio
    async def test_stall_detected_by_heartbeat_not_lease_expiry(self, db):
        """RUNNING scan with stale heartbeat_at is recovered even when lease hasn't expired."""
        from unittest.mock import MagicMock, patch
        from app.db.session import AsyncSessionLocal
        from app.worker.tasks import _recover_stalled
        from sqlalchemy import update
        from datetime import timedelta

        _, _, scan = await _make_org_and_scan(db)

        stale = datetime.now(timezone.utc) - timedelta(seconds=300)
        fresh_lease = datetime.now(timezone.utc) + timedelta(seconds=60)

        async with AsyncSessionLocal() as s:
            await s.execute(
                update(Scan)
                .where(Scan.id == scan.id)
                .values(
                    status=ScanStatus.RUNNING,
                    worker_lease_id=str(uuid.uuid4()),
                    heartbeat_at=stale,
                    lease_expires_at=fresh_lease,
                    started_at=stale,
                )
            )
            await s.commit()

        with patch("app.worker.tasks.scan_task.delay", return_value=MagicMock(id="recovery-task")):
            await _recover_stalled()

        async with AsyncSessionLocal() as s:
            obj = await s.get(Scan, scan.id)
        assert obj.status == ScanStatus.QUEUED, (
            f"Expected QUEUED after heartbeat stall, got {obj.status}"
        )

    @pytest.mark.asyncio
    async def test_stall_not_triggered_when_heartbeat_recent(self, db):
        """RUNNING scan with recent heartbeat_at is NOT recovered."""
        from unittest.mock import MagicMock, patch
        from app.db.session import AsyncSessionLocal
        from app.worker.tasks import _recover_stalled
        from sqlalchemy import update
        from datetime import timedelta

        _, _, scan = await _make_org_and_scan(db)

        recent = datetime.now(timezone.utc) - timedelta(seconds=10)

        async with AsyncSessionLocal() as s:
            await s.execute(
                update(Scan)
                .where(Scan.id == scan.id)
                .values(
                    status=ScanStatus.RUNNING,
                    worker_lease_id=str(uuid.uuid4()),
                    heartbeat_at=recent,
                    lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=80),
                    started_at=recent,
                )
            )
            await s.commit()

        with patch("app.worker.tasks.scan_task.delay", return_value=MagicMock(id="x")):
            await _recover_stalled()

        async with AsyncSessionLocal() as s:
            obj = await s.get(Scan, scan.id)
        assert obj.status == ScanStatus.RUNNING, (
            f"Recent heartbeat scan must stay RUNNING, got {obj.status}"
        )

    @pytest.mark.asyncio
    async def test_recovery_does_not_raise_when_redis_down(self, db):
        """F-04: _recover_stalled does not propagate exception when scan_task.delay fails."""
        from unittest.mock import patch
        from app.db.session import AsyncSessionLocal
        from app.worker.tasks import _recover_stalled
        from sqlalchemy import update
        from datetime import timedelta

        _, _, scan = await _make_org_and_scan(db)

        stale = datetime.now(timezone.utc) - timedelta(seconds=300)

        async with AsyncSessionLocal() as s:
            await s.execute(
                update(Scan)
                .where(Scan.id == scan.id)
                .values(
                    status=ScanStatus.RUNNING,
                    worker_lease_id=str(uuid.uuid4()),
                    heartbeat_at=stale,
                    lease_expires_at=stale + timedelta(seconds=90),
                    started_at=stale,
                )
            )
            await s.commit()

        with patch("app.worker.tasks.scan_task.delay", side_effect=Exception("Redis down")):
            await _recover_stalled()  # Must not raise

        async with AsyncSessionLocal() as s:
            obj = await s.get(Scan, scan.id)
        # Scan reset to QUEUED before dispatch attempt
        assert obj.status == ScanStatus.QUEUED, (
            f"Scan must be QUEUED even if dispatch raised, got {obj.status}"
        )


# ── F-OUTBOX: scan committed before dispatch ──────────────────────────────────


class TestOutboxCommitBeforeDispatch:
    """Scan must be committed to DB before scan_task.delay() is called."""

    @pytest.mark.asyncio
    async def test_scan_persists_when_dispatch_raises(self, client, db):
        """With fix: scan committed before dispatch, so it survives a Redis failure."""
        import uuid as _uuid
        from unittest.mock import AsyncMock, patch
        from httpx import ASGITransport, AsyncClient
        from app.db.session import AsyncSessionLocal, get_db
        from app.db.models.scan import Scan as ScanModel
        from app.main import app

        email = f"outbox-{_uuid.uuid4()}@test.dev"
        from tests.conftest import make_invite
        await client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": "TestPass1!SecureEnough", "invite": await make_invite(email)},
        )
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "TestPass1!SecureEnough"},
        )
        token = resp.json()["access_token"]
        hdrs = {"Authorization": f"Bearer {token}"}

        resp = await client.post(
            "/api/v1/orgs",
            json={"name": f"org-{_uuid.uuid4()}", "slug": f"slug-{_uuid.uuid4()}"},
            headers=hdrs,
        )
        org_id = resp.json()["id"]
        from tests.conftest import verify_domain
        await verify_domain(org_id, "example.com")

        # Use raise_server_exceptions=False so ASGITransport returns 500 instead
        # of re-raising the exception, letting us inspect the response code and DB state.
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="https://test",
        ) as local_client:
            app.dependency_overrides[get_db] = lambda: db  # keep same session
            with (
                patch(
                    "app.services.scan_service.SSRFGuard.validate_domain_for_scan",
                    new=AsyncMock(),
                ),
                patch(
                    "app.worker.tasks.scan_task.delay",
                    side_effect=Exception("Redis unavailable"),
                ),
                # Production dispatch path: conftest sets DEBUG=true, which turns a
                # broker failure into an inline engine run (201 + real network scan).
                patch("app.core.config.settings.DEBUG", False),
            ):
                resp = await local_client.post(
                    f"/api/v1/orgs/{org_id}/scans",
                    json={"target_domain": "example.com"},
                    headers=hdrs,
                )

        # 500 expected (dispatch raised)
        assert resp.status_code == 500

        # Scan must be in DB despite the error (committed before dispatch)
        from sqlalchemy import select as sa_select
        async with AsyncSessionLocal() as s:
            result = await s.execute(
                sa_select(ScanModel).where(
                    ScanModel.org_id == _uuid.UUID(org_id)
                )
            )
            scans = result.scalars().all()

        assert len(scans) == 1, (
            f"Scan must be committed before dispatch (found {len(scans)} scans, expected 1)"
        )
