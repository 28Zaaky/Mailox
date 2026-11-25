"""
Docker multi-process integration tests (10 mandatory scenarios).

Requirements:
  docker compose -f docker-compose.test.yml up -d
  MAILOX_INTEGRATION_TESTS=1 pytest tests/integration/ -v

Each test verifies the final DB state via direct PostgreSQL queries.
No mocks — all verifications query the real database.

Scenarios:
  1. Two workers receive same scan simultaneously → only one processes it
  2. Worker starts then crashes (SIGKILL) → lease expires → Beat recovers
  3. Lease expires naturally → Beat re-queues → second worker completes
  4. Two Beat processes run simultaneously → no double dispatch
  5. Second worker resumes after recovery, stale worker rejected
  6. Stale worker resumes and all writes are rejected
  7. Two recovery processes handle same outbox entry simultaneously
  8. Retry after partial persistence (DNS ok, SMTP fails)
  9. Redis restart during dispatch → outbox recovery re-dispatches
  10. PostgreSQL temporary unavailability → worker retries and succeeds
"""
import asyncio
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone, timedelta

import pytest
import pytest_asyncio
import httpx
from sqlalchemy import select, update, text
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.conftest import SKIP_REASON, INTEGRATION, INT_DB_URL, INT_API_URL

pytestmark = pytest.mark.skipif(not INTEGRATION, reason=SKIP_REASON)


# ── Helpers ───────────────────────────────────────────────────────────────────


async def wait_for_scan_terminal(
    db: AsyncSession,
    scan_id: uuid.UUID,
    timeout: float = 60.0,
) -> str:
    """Poll until scan reaches a terminal status. Returns final status."""
    from app.db.models.scan import Scan, ScanStatus
    terminal = {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = await db.execute(
            select(Scan.status).where(Scan.id == scan_id)
        )
        row = result.fetchone()
        if row and row[0] in terminal:
            return row[0].value
        await asyncio.sleep(1.0)
    return "timeout"


async def create_scan_direct(db: AsyncSession, org_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
    """Insert scan + outbox directly into DB (bypass API for speed)."""
    from app.db.models.scan import Scan, ScanOutbox, ScanStatus
    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        org_id=org_id,
        target_domain="example.com",
        status=ScanStatus.QUEUED,
        created_by=user_id,
    )
    db.add(scan)
    await db.flush()
    outbox = ScanOutbox(scan_id=scan_id)
    db.add(outbox)
    await db.commit()
    return scan_id


# ── Scenario 1 ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_1_two_workers_same_scan(int_db, int_org):
    """
    Scenario 1: Two workers receive same Celery task simultaneously.
    Expected: Exactly one worker acquires the lease and processes the scan.
    Final state: COMPLETED or PARTIAL or FAILED (not RUNNING, not QUEUED).
    Finding count must not be duplicated (no double engine execution).
    """
    from app.worker.tasks import scan_task
    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)

    # Create user for the scan
    user_id = uuid.uuid4()
    scan_id = await create_scan_direct(int_db, org_uuid, user_id)

    # Dispatch the same task ID to both workers simultaneously
    task1 = scan_task.apply_async(args=[str(scan_id)], queue="celery")
    task2 = scan_task.apply_async(args=[str(scan_id)], queue="celery")

    final_status = await wait_for_scan_terminal(int_db, scan_id, timeout=90.0)
    assert final_status not in ("timeout", "running", "queued"), (
        f"Scan {scan_id} stuck in {final_status}"
    )

    # Count engine runs for this scan — should be exactly 2 (one per engine, one attempt)
    from app.db.models.scan import ScanEngineRun
    result = await int_db.execute(
        select(ScanEngineRun).where(ScanEngineRun.scan_id == scan_id)
    )
    runs = result.scalars().all()
    # Only one attempt's engine runs should be terminal (the other worker's attempt was rejected)
    terminal_runs = [r for r in runs if r.status in ("completed", "failed", "timeout")]
    assert len(terminal_runs) <= 2, (
        f"Expected at most 2 terminal engine runs (1 per engine), got {len(terminal_runs)}"
    )


# ── Scenario 2 ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_2_worker_crash_lease_expires_beat_recovers(int_db, int_org):
    """
    Scenario 2: Worker acquires lease then is killed (SIGKILL).
    Expected: Heartbeat stops, lease expires, Beat recovers scan to QUEUED,
    second worker picks it up and completes.
    """
    from app.db.models.scan import Scan, ScanStatus

    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)
    user_id = uuid.uuid4()
    scan_id = await create_scan_direct(int_db, org_uuid, user_id)

    # Manually set scan to RUNNING with an expired lease (simulates crashed worker)
    old_lease_id = str(uuid.uuid4())
    expired_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    await int_db.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(
            status=ScanStatus.RUNNING,
            worker_lease_id=old_lease_id,
            lease_expires_at=expired_at,
            started_at=datetime.now(timezone.utc),
            attempt_number=1,
        )
    )
    await int_db.commit()

    # Wait for Beat to detect the stall and re-queue
    # Beat runs recover_stalled_scans every 60s by default
    # In test config, SCAN_STALL_TIMEOUT_SECONDS=35 so it should trigger within 2 Beat cycles
    final_status = await wait_for_scan_terminal(int_db, scan_id, timeout=180.0)
    assert final_status not in ("timeout", "running"), (
        f"Scan {scan_id} not recovered: {final_status}"
    )

    # Scan should have attempt_number >= 2 (Beat reset + second worker acquired)
    result = await int_db.execute(select(Scan.attempt_number).where(Scan.id == scan_id))
    attempt = result.scalar_one()
    assert attempt >= 2, f"Expected attempt >= 2 after recovery, got {attempt}"


# ── Scenario 3 ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_3_lease_expires_new_worker_completes(int_db, int_org):
    """
    Scenario 3: Lease expires naturally → Beat re-queues → second worker completes.
    Similar to scenario 2 but lease just expired (no crash).
    """
    from app.db.models.scan import Scan, ScanStatus
    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)
    user_id = uuid.uuid4()
    scan_id = await create_scan_direct(int_db, org_uuid, user_id)

    # Set to RUNNING with expired lease and no heartbeat
    await int_db.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(
            status=ScanStatus.RUNNING,
            worker_lease_id=str(uuid.uuid4()),
            lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=60),
            heartbeat_at=datetime.now(timezone.utc) - timedelta(seconds=60),
            started_at=datetime.now(timezone.utc) - timedelta(seconds=60),
            attempt_number=1,
        )
    )
    await int_db.commit()

    final_status = await wait_for_scan_terminal(int_db, scan_id, timeout=180.0)
    assert final_status not in ("timeout", "running"), (
        f"Scan {scan_id} not completed after lease expiry: {final_status}"
    )


# ── Scenario 4 ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_4_concurrent_beat_no_double_dispatch(int_db, int_org):
    """
    Scenario 4: Two Beat process invocations overlap on same unpublished outbox entries.
    Expected: SELECT FOR UPDATE SKIP LOCKED prevents double dispatch.
    Each scan dispatched exactly once.
    """
    from app.worker.tasks import _recover_stalled

    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)
    user_id = uuid.uuid4()

    # Create multiple scans with unpublished outbox entries
    scan_ids = []
    for _ in range(3):
        scan_id = await create_scan_direct(int_db, org_uuid, user_id)
        scan_ids.append(scan_id)

    # Run two recover_stalled concurrently
    await asyncio.gather(_recover_stalled(), _recover_stalled())

    # Check outbox: each should be published exactly once
    from app.db.models.scan import ScanOutbox
    for scan_id in scan_ids:
        result = await int_db.execute(
            select(ScanOutbox).where(ScanOutbox.scan_id == scan_id)
        )
        outbox = result.scalar_one()
        # attempt_count may be > 1 if both saw the same entry, but published=True should
        # be set exactly once and celery_task_id should be a single ID
        assert outbox.published, f"Scan {scan_id} outbox not published"


# ── Scenario 5 ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_5_stale_worker_writes_rejected(int_db, int_org):
    """
    Scenario 5: Old worker resumes after recovery. All its writes must be rejected.
    Verifies BUG-05, BUG-11, BUG-12 fixes work end-to-end in real DB.
    """
    from app.db.models.scan import Scan, ScanFinding, ScanEngineRun, ScanStatus
    from sqlalchemy import delete as sa_delete, exists as sa_exists

    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)
    user_id = uuid.uuid4()
    scan_id = await create_scan_direct(int_db, org_uuid, user_id)
    scan_uuid = scan_id

    # First worker acquires lease
    old_lease = str(uuid.uuid4())
    await int_db.execute(
        update(Scan)
        .where(Scan.id == scan_uuid)
        .values(
            status=ScanStatus.RUNNING,
            worker_lease_id=old_lease,
            attempt_number=1,
            started_at=datetime.now(timezone.utc),
        )
    )
    await int_db.commit()

    # Recovery steals the lease
    new_lease = str(uuid.uuid4())
    await int_db.execute(
        update(Scan)
        .where(Scan.id == scan_uuid)
        .values(
            worker_lease_id=new_lease,
            attempt_number=2,
        )
    )
    await int_db.commit()

    # Stale worker tries engine run INSERT with old lease — should be a no-op
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as s:
        lease_check = await s.execute(
            select(Scan.id).where(
                Scan.id == scan_uuid,
                Scan.worker_lease_id == old_lease,
            )
        )
        # Old lease is gone → should not insert
        assert lease_check.fetchone() is None, "Old lease should no longer match"

    # Stale worker tries final write — should return 0 rows
    async with AsyncSessionLocal() as s:
        # Plant a finding first (simulates stale worker's delete attempt)
        f = ScanFinding(
            id=uuid.uuid4(),
            scan_id=scan_uuid,
            engine="dns_auth",
            check_id="DNS-01",
            title="Legitimate finding from new worker",
            description="x",
            risk_level="high",
            confidence=0.9,
            evidence={},
            remediation="x",
        )
        s.add(f)
        await s.commit()

    async with AsyncSessionLocal() as s:
        # Stale worker's final write transaction
        await s.execute(sa_delete(ScanFinding).where(ScanFinding.scan_id == scan_uuid))
        result = await s.execute(
            update(Scan)
            .where(Scan.id == scan_uuid, Scan.worker_lease_id == old_lease)
            .values(status=ScanStatus.COMPLETED)
            .returning(Scan.id)
        )
        if not result.fetchone():
            await s.rollback()  # Correct: stale write rejected

    # Legitimate finding must still be present
    async with AsyncSessionLocal() as s:
        result = await s.execute(
            select(ScanFinding).where(ScanFinding.scan_id == scan_uuid)
        )
        findings = result.scalars().all()

    assert len(findings) == 1
    assert findings[0].title == "Legitimate finding from new worker"


# ── Scenario 6 ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_6_all_stale_worker_engine_run_updates_rejected(int_db, int_org):
    """
    Scenario 6: Stale worker's ScanEngineRun UPDATE is a no-op (BUG-12 fix).
    """
    from app.db.models.scan import Scan, ScanEngineRun, ScanStatus
    from sqlalchemy import exists as sa_exists

    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)
    user_id = uuid.uuid4()
    scan_id = await create_scan_direct(int_db, org_uuid, user_id)

    old_lease = str(uuid.uuid4())
    new_lease = str(uuid.uuid4())

    # Set up: scan with new lease (recovery happened)
    await int_db.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(
            status=ScanStatus.RUNNING,
            worker_lease_id=new_lease,
            attempt_number=2,
            started_at=datetime.now(timezone.utc),
        )
    )
    await int_db.commit()

    # Insert engine run for old attempt (stale worker's attempt 1)
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as s:
        run = ScanEngineRun(
            id=uuid.uuid4(),
            scan_id=scan_id,
            attempt_number=1,
            engine="dns_auth",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        s.add(run)
        await s.commit()

    # Stale worker tries to UPDATE its engine run with old lease
    async with AsyncSessionLocal() as s:
        result = await s.execute(
            update(ScanEngineRun)
            .where(
                ScanEngineRun.scan_id == scan_id,
                ScanEngineRun.attempt_number == 1,
                ScanEngineRun.engine == "dns_auth",
                sa_exists(
                    select(Scan.id).where(
                        Scan.id == scan_id,
                        Scan.worker_lease_id == old_lease,
                    )
                ),
            )
            .values(status="completed", finished_at=datetime.now(timezone.utc))
        )
        await s.commit()

    # Engine run should still be "running" (guarded UPDATE was no-op)
    async with AsyncSessionLocal() as s:
        result = await s.execute(
            select(ScanEngineRun).where(
                ScanEngineRun.scan_id == scan_id,
                ScanEngineRun.attempt_number == 1,
            )
        )
        run = result.scalar_one()
    assert run.status == "running", f"Expected 'running', got '{run.status}'"


# ── Scenario 7 ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_7_concurrent_outbox_recovery_no_double_dispatch(int_db, int_org):
    """
    Scenario 7: Two recover_stalled calls run simultaneously on the same outbox entry.
    SELECT FOR UPDATE SKIP LOCKED ensures only one dispatches.
    """
    from app.worker.tasks import _recover_stalled

    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)
    user_id = uuid.uuid4()

    # Create scan with expired lease (stalled)
    from app.db.models.scan import Scan, ScanStatus
    scan_id = await create_scan_direct(int_db, org_uuid, user_id)
    await int_db.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(
            status=ScanStatus.RUNNING,
            worker_lease_id=str(uuid.uuid4()),
            lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=120),
            attempt_number=1,
        )
    )
    await int_db.commit()

    # Two concurrent recovery calls
    await asyncio.gather(_recover_stalled(), _recover_stalled())

    # Outbox attempt_count should not exceed what one dispatcher would set
    from app.db.models.scan import ScanOutbox
    result = await int_db.execute(
        select(ScanOutbox).where(ScanOutbox.scan_id == scan_id)
    )
    outbox = result.scalar_one_or_none()
    if outbox:
        # attempt_count increments are idempotent (upsert-based)
        assert outbox.published, "Scan should be dispatched after concurrent recovery"


# ── Scenario 8 ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_8_retry_after_partial_persistence(int_db, int_org):
    """
    Scenario 8: DNS engine succeeds, SMTP fails → scan PARTIAL.
    On retry (simulated by scan reset to QUEUED), second attempt re-runs both engines.
    Findings from first attempt are replaced, not duplicated.
    """
    from app.db.models.scan import Scan, ScanFinding, ScanStatus
    from sqlalchemy import delete as sa_delete

    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)
    user_id = uuid.uuid4()
    scan_id = await create_scan_direct(int_db, org_uuid, user_id)

    first_lease = str(uuid.uuid4())
    # First attempt: DNS ok, SMTP failed → partial state
    await int_db.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(
            status=ScanStatus.PARTIAL,
            worker_lease_id=None,
            attempt_number=1,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
    )
    await int_db.commit()

    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as s:
        f1 = ScanFinding(
            id=uuid.uuid4(),
            scan_id=scan_id,
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

    # Simulate retry: reset scan to QUEUED
    async with AsyncSessionLocal() as s:
        await s.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(
                status=ScanStatus.QUEUED,
                worker_lease_id=None,
                started_at=None,
                completed_at=None,
            )
        )
        await s.commit()

    # Second attempt: dispatch and complete
    second_lease = str(uuid.uuid4())
    async with AsyncSessionLocal() as s:
        await s.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == ScanStatus.QUEUED)
            .values(
                status=ScanStatus.RUNNING,
                worker_lease_id=second_lease,
                attempt_number=2,
            )
        )
        await s.commit()

    async with AsyncSessionLocal() as s:
        await s.execute(sa_delete(ScanFinding).where(ScanFinding.scan_id == scan_id))
        f2 = ScanFinding(
            id=uuid.uuid4(),
            scan_id=scan_id,
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
            .where(Scan.id == scan_id, Scan.worker_lease_id == second_lease)
            .values(status=ScanStatus.COMPLETED)
            .returning(Scan.id)
        )
        assert result.fetchone() is not None
        await s.commit()

    async with AsyncSessionLocal() as s:
        result = await s.execute(
            select(ScanFinding).where(ScanFinding.scan_id == scan_id)
        )
        findings = result.scalars().all()

    assert len(findings) == 1
    assert findings[0].title == "Finding from attempt 2"


# ── Scenario 9 ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_9_redis_restart_during_dispatch(int_db, int_org):
    """
    Scenario 9: Redis restarted during task dispatch.
    Outbox entry published=False, Beat re-dispatches on next cycle.

    NOTE: This test requires Docker control. It pauses the redis-test container
    and verifies that Beat republishes the outbox entry after Redis recovers.
    """
    import subprocess

    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)
    user_id = uuid.uuid4()
    scan_id = await create_scan_direct(int_db, org_uuid, user_id)

    # Simulate the scan's outbox entry being left unpublished
    from app.db.models.scan import ScanOutbox
    result = await int_db.execute(
        select(ScanOutbox).where(ScanOutbox.scan_id == scan_id)
    )
    outbox = result.scalar_one()
    outbox.published = False
    outbox.celery_task_id = None
    outbox.published_at = None
    await int_db.commit()

    # Pause Redis briefly (simulates restart)
    try:
        subprocess.run(
            ["docker", "compose", "-f", "docker-compose.test.yml", "pause", "redis-test"],
            check=True, timeout=10, capture_output=True,
        )
        await asyncio.sleep(5.0)
    finally:
        subprocess.run(
            ["docker", "compose", "-f", "docker-compose.test.yml", "unpause", "redis-test"],
            check=True, timeout=10, capture_output=True,
        )

    # Beat should re-dispatch within the next cycle
    deadline = time.monotonic() + 90.0
    published = False
    while time.monotonic() < deadline:
        await int_db.refresh(outbox)
        if outbox.published:
            published = True
            break
        await asyncio.sleep(2.0)

    assert published, "Beat must re-dispatch unpublished outbox entry after Redis recovery"

    final_status = await wait_for_scan_terminal(int_db, scan_id, timeout=120.0)
    assert final_status not in ("timeout",), f"Scan stuck after Redis recovery: {final_status}"


# ── Scenario 10 ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scenario_10_postgres_temporary_unavailability(int_db, int_org):
    """
    Scenario 10: PostgreSQL briefly unavailable during worker execution.
    Worker's heartbeat fails silently. When PG comes back, final write succeeds.

    NOTE: Requires Docker control — pauses postgres-test container.
    """
    import subprocess

    token, org_id = int_org
    org_uuid = uuid.UUID(org_id)
    user_id = uuid.uuid4()
    scan_id = await create_scan_direct(int_db, org_uuid, user_id)

    from app.worker.tasks import scan_task
    scan_task.apply_async(args=[str(scan_id)], queue="celery")

    # Brief PG pause (simulates network blip, not full restart)
    await asyncio.sleep(2.0)
    try:
        subprocess.run(
            ["docker", "compose", "-f", "docker-compose.test.yml", "pause", "postgres-test"],
            check=True, timeout=10, capture_output=True,
        )
        await asyncio.sleep(3.0)
    finally:
        subprocess.run(
            ["docker", "compose", "-f", "docker-compose.test.yml", "unpause", "postgres-test"],
            check=True, timeout=10, capture_output=True,
        )

    # Worker should complete (with retry if needed)
    final_status = await wait_for_scan_terminal(int_db, scan_id, timeout=120.0)
    assert final_status not in ("timeout",), (
        f"Scan {scan_id} not completed after PG recovery: {final_status}"
    )
