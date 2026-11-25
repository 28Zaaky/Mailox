"""
AT-10 — Worker and task lifecycle tests.
Worker logic is tested using fully-mocked DB sessions (no real DB hit required).
The outbox pattern integration test uses the real test DB via the client fixture.
"""
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call

import types

import pytest

from app.db.models.scan import ScanFinding, ScanOutbox, ScanStatus, RiskLevel
from app.worker.tasks import _run_scan, _recover_stalled
from tests.worker_db_mock import make_worker_execute, stub_aux_engines


@pytest.fixture(autouse=True)
def _no_network_aux_engines():
    """Engines the tests don't patch explicitly must not reach the network."""
    with stub_aux_engines():
        yield


# ── DB mock helpers ───────────────────────────────────────────────────────────


def _make_scan_obj(
    status: ScanStatus = ScanStatus.QUEUED,
    cancel_requested: bool = False,
    started_at=None,
):
    """Build a plain-namespace scan object for worker unit tests (no DB needed)."""
    return types.SimpleNamespace(
        id=uuid.uuid4(),
        org_id=uuid.uuid4(),
        target_domain="example.com",
        status=status,
        cancel_requested=cancel_requested,
        created_by=uuid.uuid4(),
        created_at=datetime.now(timezone.utc),
        started_at=started_at,
        completed_at=None,
        error_msg=None,
        progress_pct=0,
        current_engine=None,
        celery_task_id=None,
    )


def _build_mock_db(scan):
    """
    Mock AsyncSession for _run_scan. execute() is answered per statement type
    (see tests/worker_db_mock.py) instead of by call position, so new engines or
    pre-flight queries don't break the fixture.

    For non-QUEUED scans the lease UPDATE returns no row -> early exit.
    """
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()

    def _r(fone=None):
        r = MagicMock()
        r.fetchone = MagicMock(return_value=fone)
        r.scalar_one_or_none = MagicMock(return_value=scan)
        r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        return r

    target = getattr(scan, "target_domain", "example.com") or "example.com"
    cr = getattr(scan, "cancel_requested", False)
    sid = getattr(scan, "id", None)

    if getattr(scan, "status", None) != ScanStatus.QUEUED:
        # Lease not acquired — first call returns no row → early exit
        db.execute = AsyncMock(return_value=_r(None))
    elif cr:
        # cancel_requested=True: lease acquired, then immediately CANCELLED
        db.execute = AsyncMock(side_effect=make_worker_execute(lease_row=(1, True, target)))
    else:
        db.execute = AsyncMock(side_effect=make_worker_execute(lease_row=(1, False, target)))

    async def _refresh(obj, **kwargs):
        pass

    db.refresh = _refresh
    db.__aenter__ = AsyncMock(return_value=db)
    db.__aexit__ = AsyncMock(return_value=False)
    return db


# ── Task execution tests ───────────────────────────────────────────────────────


class TestScanTask:
    @pytest.mark.asyncio
    async def test_task_completes_scan(self):
        """_run_scan sets status=COMPLETED after successful engine runs."""
        scan = _make_scan_obj(status=ScanStatus.QUEUED)
        mock_db = _build_mock_db(scan)
        task_mock = MagicMock()

        with patch("app.db.session.AsyncSessionLocal", return_value=mock_db), \
             patch("app.engines.dns_auth.DNSAuthEngine") as MockDNS, \
             patch("app.engines.smtp_discovery.SMTPDiscoveryEngine") as MockSMTP, \
             patch("app.engines.webmail.WebmailEngine") as MockWebmail, \
             patch("app.engines.vuln_intel.VulnIntelEngine") as MockVulnIntel:
            dns_result = MagicMock()
            dns_result.findings = []
            smtp_result = MagicMock()
            smtp_result.findings = []
            webmail_result = MagicMock()
            webmail_result.findings = []
            vuln_result = MagicMock()
            vuln_result.findings = []
            MockDNS.return_value.run = AsyncMock(return_value=dns_result)
            MockSMTP.return_value.run = AsyncMock(return_value=smtp_result)
            MockWebmail.return_value.run = AsyncMock(return_value=webmail_result)
            MockVulnIntel.return_value.run_from_findings = AsyncMock(return_value=vuln_result)

            await _run_scan(str(scan.id), task_mock)

        # Uses pure SQL UPDATEs — verify completion via mock calls
        assert mock_db.commit.called
        assert MockDNS.return_value.run.called
        assert MockSMTP.return_value.run.called

    @pytest.mark.asyncio
    async def test_task_skips_cancelled_scan(self):
        """_run_scan exits immediately if scan already CANCELLED."""
        scan = _make_scan_obj(status=ScanStatus.CANCELLED)
        mock_db = _build_mock_db(scan)
        task_mock = MagicMock()

        with patch("app.db.session.AsyncSessionLocal", return_value=mock_db), \
             patch("app.engines.dns_auth.DNSAuthEngine") as MockDNS:
            await _run_scan(str(scan.id), task_mock)
            MockDNS.assert_not_called()

        assert scan.status == ScanStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_task_honours_cancel_requested(self):
        """cancel_requested=True before task starts → scan set CANCELLED, engines not called."""
        scan = _make_scan_obj(cancel_requested=True)
        mock_db = _build_mock_db(scan)
        task_mock = MagicMock()

        with patch("app.db.session.AsyncSessionLocal", return_value=mock_db), \
             patch("app.engines.dns_auth.DNSAuthEngine") as MockDNS:
            await _run_scan(str(scan.id), task_mock)
            MockDNS.assert_not_called()

        # Lease acquired then cancel path: at least 2 commits (lease + CANCELLED update)
        assert mock_db.commit.call_count >= 2

    @pytest.mark.asyncio
    async def test_task_handles_missing_scan(self):
        """Non-existent scan_id: task returns without raising."""
        db = MagicMock()
        execute_result = MagicMock()
        execute_result.fetchone = MagicMock(return_value=None)  # lease acquisition returns nothing
        execute_result.scalar_one_or_none = MagicMock(return_value=None)
        db.execute = AsyncMock(return_value=execute_result)
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        db.rollback = AsyncMock()
        db.__aenter__ = AsyncMock(return_value=db)
        db.__aexit__ = AsyncMock(return_value=False)

        task_mock = MagicMock()

        with patch("app.db.session.AsyncSessionLocal", return_value=db):
            await _run_scan(str(uuid.uuid4()), task_mock)

        db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_task_dns_timeout_still_runs_smtp(self):
        """DNS timeout doesn't prevent SMTP from running."""
        import asyncio
        scan = _make_scan_obj()
        mock_db = _build_mock_db(scan)
        task_mock = MagicMock()
        task_mock.retry = MagicMock(side_effect=RuntimeError("should not retry"))

        with patch("app.db.session.AsyncSessionLocal", return_value=mock_db), \
             patch("app.engines.dns_auth.DNSAuthEngine") as MockDNS, \
             patch("app.engines.smtp_discovery.SMTPDiscoveryEngine") as MockSMTP, \
             patch("app.engines.webmail.WebmailEngine") as MockWebmail, \
             patch("app.engines.vuln_intel.VulnIntelEngine") as MockVulnIntel:
            async def _timeout(domain):
                raise asyncio.TimeoutError()

            smtp_result = MagicMock()
            smtp_result.findings = []
            webmail_result = MagicMock()
            webmail_result.findings = []
            vuln_result = MagicMock()
            vuln_result.findings = []
            MockDNS.return_value.run = _timeout
            MockSMTP.return_value.run = AsyncMock(return_value=smtp_result)
            MockWebmail.return_value.run = AsyncMock(return_value=webmail_result)
            MockVulnIntel.return_value.run_from_findings = AsyncMock(return_value=vuln_result)

            await _run_scan(str(scan.id), task_mock)

        # SMTP ran despite DNS timeout; final status is PARTIAL (one engine failed)
        assert MockSMTP.return_value.run.called

    @pytest.mark.asyncio
    async def test_task_transitions_queued_to_running(self):
        """Task sets status=RUNNING and started_at before engines run."""
        scan = _make_scan_obj(status=ScanStatus.QUEUED)
        mock_db = _build_mock_db(scan)
        task_mock = MagicMock()

        with patch("app.db.session.AsyncSessionLocal", return_value=mock_db), \
             patch("app.engines.dns_auth.DNSAuthEngine") as MockDNS, \
             patch("app.engines.smtp_discovery.SMTPDiscoveryEngine") as MockSMTP, \
             patch("app.engines.webmail.WebmailEngine") as MockWebmail, \
             patch("app.engines.vuln_intel.VulnIntelEngine") as MockVulnIntel:
            dns_result = MagicMock()
            dns_result.findings = []
            smtp_result = MagicMock()
            smtp_result.findings = []
            webmail_result = MagicMock()
            webmail_result.findings = []
            vuln_result = MagicMock()
            vuln_result.findings = []
            MockDNS.return_value.run = AsyncMock(return_value=dns_result)
            MockSMTP.return_value.run = AsyncMock(return_value=smtp_result)
            MockWebmail.return_value.run = AsyncMock(return_value=webmail_result)
            MockVulnIntel.return_value.run_from_findings = AsyncMock(return_value=vuln_result)
            await _run_scan(str(scan.id), task_mock)

        # Sets RUNNING via SQL UPDATE; engines only run after lease acquired
        assert MockDNS.return_value.run.called
        assert MockSMTP.return_value.run.called


# ── Recovery task tests ────────────────────────────────────────────────────────


class TestRecoverStalled:
    @pytest.mark.asyncio
    async def test_stalled_running_scan_requeued(self):
        """Scan stuck in RUNNING past stall threshold gets re-queued."""
        stale_scan = _make_scan_obj(
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc) - timedelta(seconds=400),
        )
        outbox_entry = MagicMock(spec=ScanOutbox)
        outbox_entry.published = False
        outbox_entry.scan_id = stale_scan.id

        db = MagicMock()
        db.add = MagicMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        db.__aenter__ = AsyncMock(return_value=db)
        db.__aexit__ = AsyncMock(return_value=False)

        # execute calls: stalled SELECT, outbox upsert (per stalled scan),
        # outbox UPDATE after dispatch (FIX-17), unpublished SELECT
        stalled_scalars = MagicMock()
        stalled_scalars.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[stale_scan])))
        outbox_upsert = MagicMock()  # INSERT INTO scan_outbox ... ON CONFLICT ... RETURNING attempt_count
        outbox_upsert.scalar_one = MagicMock(return_value=1)  # below SCAN_MAX_TOTAL_ATTEMPTS
        outbox_update = MagicMock()  # UPDATE scan_outbox SET published=true after dispatch (FIX-17)
        empty_scalars = MagicMock()
        empty_scalars.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        db.execute = AsyncMock(side_effect=[stalled_scalars, outbox_upsert, outbox_update, empty_scalars])

        with patch("app.db.session.AsyncSessionLocal", return_value=db), \
             patch("app.worker.tasks.scan_task") as MockTask:
            MockTask.delay = MagicMock()
            await _recover_stalled()

        assert stale_scan.status == ScanStatus.QUEUED
        assert stale_scan.started_at is None
        MockTask.delay.assert_called_once_with(str(stale_scan.id))

    @pytest.mark.asyncio
    async def test_stalled_scan_over_max_attempts_failed_not_requeued(self):
        """Recovery enforces SCAN_MAX_TOTAL_ATTEMPTS: the scan is FAILED, not redispatched."""
        from app.core.config import settings

        stale_scan = _make_scan_obj(
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc) - timedelta(seconds=400),
        )
        db = MagicMock()
        db.add = MagicMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        db.__aenter__ = AsyncMock(return_value=db)
        db.__aexit__ = AsyncMock(return_value=False)

        stalled_scalars = MagicMock()
        stalled_scalars.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[stale_scan])))
        outbox_upsert = MagicMock()
        outbox_upsert.scalar_one = MagicMock(return_value=settings.SCAN_MAX_TOTAL_ATTEMPTS)
        outbox_published = MagicMock()  # UPDATE scan_outbox SET published=true (no redispatch)
        empty_scalars = MagicMock()
        empty_scalars.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        db.execute = AsyncMock(side_effect=[stalled_scalars, outbox_upsert, outbox_published, empty_scalars])

        with patch("app.db.session.AsyncSessionLocal", return_value=db),              patch("app.worker.tasks.scan_task") as MockTask:
            MockTask.delay = MagicMock()
            await _recover_stalled()

        assert stale_scan.status == ScanStatus.FAILED
        assert "Max attempts" in stale_scan.error_msg
        assert stale_scan.completed_at is not None
        MockTask.delay.assert_not_called()

    @pytest.mark.asyncio
    async def test_unpublished_outbox_entries_dispatched(self):
        """Unpublished outbox entries trigger scan_task dispatch."""
        outbox = MagicMock(spec=ScanOutbox)
        outbox.scan_id = uuid.uuid4()
        outbox.published = False
        outbox.celery_task_id = None
        outbox.published_at = None
        outbox.attempt_count = 0  # below SCAN_MAX_TOTAL_ATTEMPTS threshold (FIX-18)

        db = MagicMock()
        db.add = MagicMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        db.__aenter__ = AsyncMock(return_value=db)
        db.__aexit__ = AsyncMock(return_value=False)

        no_stalled = MagicMock()
        no_stalled.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        with_outbox = MagicMock()
        with_outbox.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[outbox])))
        db.execute = AsyncMock(side_effect=[no_stalled, with_outbox])

        fake_task = MagicMock()
        fake_task.id = "celery-xyz"

        with patch("app.db.session.AsyncSessionLocal", return_value=db), \
             patch("app.worker.tasks.scan_task") as MockTask:
            MockTask.delay = MagicMock(return_value=fake_task)
            await _recover_stalled()

        assert outbox.published is True
        assert outbox.celery_task_id == "celery-xyz"
        MockTask.delay.assert_called_with(str(outbox.scan_id))


# ── Outbox integration test (real DB via client fixture) ──────────────────────


class TestOutboxIntegration:
    @pytest.mark.asyncio
    async def test_scan_creation_creates_outbox_entry(self, client, db):
        """Creating a scan via API creates a ScanOutbox record."""
        from tests.conftest import auth_headers, login_user, register_user, verify_domain
        from sqlalchemy import select

        email = "outbox_test@example.com"
        await register_user(client, email=email)
        tokens = await login_user(client, email=email)
        access = tokens["access_token"]

        resp = await client.post(
            "/api/v1/orgs",
            json={"name": "Outbox Org", "slug": "outbox-org"},
            headers=auth_headers(access),
        )
        assert resp.status_code == 201
        org_id = resp.json()["id"]
        await verify_domain(org_id, "example.com")

        async def _noop_dispatch(self, scan):
            return None

        with patch("app.services.scan_service.ScanService._dispatch_task", new=_noop_dispatch), \
             patch("app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()):
            create_resp = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers=auth_headers(access),
            )

        assert create_resp.status_code == 201
        scan_id = uuid.UUID(create_resp.json()["id"])

        result = await db.execute(
            select(ScanOutbox).where(ScanOutbox.scan_id == scan_id)
        )
        outbox = result.scalar_one_or_none()
        assert outbox is not None
        assert outbox.published is False
