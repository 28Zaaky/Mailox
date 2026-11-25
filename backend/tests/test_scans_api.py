"""
AT-09 — Scan API tests.
Engines are mocked — scan tests focus on API, auth, RBAC, tenant isolation, quota.

- _mock_scan_service_ok: mocks entire create_and_run_scan (most tests).
- _mock_scan_dispatch_inline: mocks only _dispatch_task to run engines inline
  in the same test DB session, so the scan is COMPLETED on return.
  Used by persistence and cancel tests that need a real DB record.
"""
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient

from tests.conftest import auth_headers, login_user, register_user, verify_domain


# ── Engine mock helpers ────────────────────────────────────────────────────────


def _mock_scan_service_ok(findings_count: int = 0):
    """Patch ScanService.create_and_run_scan to return a fake completed scan instantly."""
    from app.db.models.scan import Scan, ScanStatus

    async def _fake_create(
        self, org_id, target_domain, created_by, idempotency_key=None,
        project_id=None, profile_id=None, skip_domain_verification=False,
    ):
        scan = MagicMock(spec=Scan)
        scan.id = uuid.uuid4()
        scan.org_id = org_id
        scan.target_domain = target_domain
        scan.status = ScanStatus.COMPLETED
        scan.created_by = created_by
        scan.created_at = datetime.now(timezone.utc)
        scan.started_at = datetime.now(timezone.utc)
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_msg = None
        scan.findings = []
        scan.quota_tokens_used = 1
        scan.progress_pct = 100
        scan.current_engine = None
        scan.idempotency_key = idempotency_key
        scan.project_id = project_id
        scan.profile_id = profile_id
        scan.risk_score = None
        return scan

    return patch(
        "app.services.scan_service.ScanService.create_and_run_scan",
        new=_fake_create,
    )


def _mock_scan_dispatch_inline():
    """
    Mock _dispatch_task to run engines inline in the same test DB session.
    The scan is updated to COMPLETED before create_and_run_scan returns.
    """
    from app.db.models.scan import Scan, ScanFinding, ScanStatus, RiskLevel
    from sqlalchemy import select

    async def _inline(self, scan: Scan):
        # Run mock engines (empty findings via patched _run_engines)
        all_findings = await self._run_engines(scan.target_domain)

        for finding in all_findings:
            db_finding = ScanFinding(
                id=finding.id,
                scan_id=scan.id,
                engine=finding.engine,
                check_id=finding.check_id,
                title=finding.title,
                description=finding.description,
                risk_level=RiskLevel(finding.risk_level.value),
                confidence=finding.confidence,
                evidence=[e.model_dump(mode="json") for e in finding.evidence],
                remediation=finding.remediation,
                created_at=finding.detected_at,
            )
            self.db.add(db_finding)

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.progress_pct = 100
        scan.current_engine = None
        await self.db.flush()
        return None

    return patch(
        "app.services.scan_service.ScanService._dispatch_task",
        new=_inline,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _create_org_and_get_tokens(client: AsyncClient, suffix: str = "") -> tuple[str, str]:
    """Register user, login, create org. Returns (access_token, org_id)."""
    email = f"scan_user_{suffix}@example.com"
    await register_user(client, email=email)
    tokens = await login_user(client, email=email)
    access = tokens["access_token"]

    resp = await client.post(
        "/api/v1/orgs",
        json={"name": f"Scan Org {suffix}", "slug": f"scan-org-{suffix}"},
        headers=auth_headers(access),
    )
    assert resp.status_code == 201
    org_id = resp.json()["id"]
    # SaaS edition: scans are only accepted on a domain the org has verified
    await verify_domain(org_id, "example.com")
    return access, org_id


# ── AT-09 Tests ───────────────────────────────────────────────────────────────


class TestScanCreation:
    @pytest.mark.asyncio
    async def test_create_scan_success(self, client: AsyncClient):
        access, org_id = await _create_org_and_get_tokens(client, "create")

        with _mock_scan_service_ok(), \
             patch("app.services.scan_service.ScanService._check_quota", new=AsyncMock()):
            resp = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers=auth_headers(access),
            )

        assert resp.status_code == 201
        body = resp.json()
        assert body["target_domain"] == "example.com"
        assert body["status"] == "completed"
        assert "id" in body

    @pytest.mark.asyncio
    async def test_create_scan_invalid_domain(self, client: AsyncClient):
        access, org_id = await _create_org_and_get_tokens(client, "invalid-domain")
        resp = await client.post(
            f"/api/v1/orgs/{org_id}/scans",
            json={"target_domain": "not_a_domain!!!"},
            headers=auth_headers(access),
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_create_scan_unauthenticated(self, client: AsyncClient):
        resp = await client.post(
            f"/api/v1/orgs/{uuid.uuid4()}/scans",
            json={"target_domain": "example.com"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_create_scan_domain_too_long(self, client: AsyncClient):
        access, org_id = await _create_org_and_get_tokens(client, "toolong")
        long_domain = "a" * 250 + ".com"
        resp = await client.post(
            f"/api/v1/orgs/{org_id}/scans",
            json={"target_domain": long_domain},
            headers=auth_headers(access),
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_create_scan_quota_exceeded(self, client: AsyncClient):
        access, org_id = await _create_org_and_get_tokens(client, "quota")

        async def _always_quota(self, org_id):
            from fastapi import HTTPException
            raise HTTPException(status_code=429, detail="Daily scan quota exceeded")

        with patch("app.services.scan_service.ScanService._check_quota", new=_always_quota):
            resp = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers=auth_headers(access),
            )
        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_create_scan_idempotency_returns_existing(self, client: AsyncClient):
        """Same Idempotency-Key returns the existing scan instead of creating a new one."""
        access, org_id = await _create_org_and_get_tokens(client, "idem")

        with _mock_scan_dispatch_inline(), \
             patch("app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()), \
             patch("app.services.scan_service.ScanService._run_engines", new=AsyncMock(return_value=[])):
            resp1 = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers={**auth_headers(access), "Idempotency-Key": "key-abc-123"},
            )
            resp2 = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers={**auth_headers(access), "Idempotency-Key": "key-abc-123"},
            )

        assert resp1.status_code == 201
        assert resp2.status_code == 201
        assert resp1.json()["id"] == resp2.json()["id"]


class TestScanRead:
    @pytest.mark.asyncio
    async def test_list_scans_own_org(self, client: AsyncClient):
        access, org_id = await _create_org_and_get_tokens(client, "list")
        resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans",
            headers=auth_headers(access),
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_get_scan_nonexistent_404(self, client: AsyncClient):
        access, org_id = await _create_org_and_get_tokens(client, "get404")
        fake_scan_id = uuid.uuid4()
        resp = await client.get(
            f"/api/v1/scans/{fake_scan_id}?org_id={org_id}",
            headers=auth_headers(access),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_scans_unauthenticated(self, client: AsyncClient):
        resp = await client.get(f"/api/v1/orgs/{uuid.uuid4()}/scans")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_list_scans_pagination(self, client: AsyncClient):
        """limit and offset query params accepted without error."""
        access, org_id = await _create_org_and_get_tokens(client, "pagination")
        resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans?limit=10&offset=0",
            headers=auth_headers(access),
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestScanTenantIsolation:
    @pytest.mark.asyncio
    async def test_cross_tenant_scan_read_returns_404(self, client: AsyncClient):
        """User A cannot read org B's scans — always 404, never 403."""
        access_a, org_id_a = await _create_org_and_get_tokens(client, "iso-a")
        access_b, org_id_b = await _create_org_and_get_tokens(client, "iso-b")

        resp = await client.get(
            f"/api/v1/orgs/{org_id_b}/scans",
            headers=auth_headers(access_a),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cross_tenant_scan_get_returns_404(self, client: AsyncClient):
        access_a, org_id_a = await _create_org_and_get_tokens(client, "iso-get-a")
        access_b, org_id_b = await _create_org_and_get_tokens(client, "iso-get-b")

        fake_scan_id = uuid.uuid4()
        resp = await client.get(
            f"/api/v1/scans/{fake_scan_id}?org_id={org_id_b}",
            headers=auth_headers(access_a),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cross_tenant_scan_findings_returns_404(self, client: AsyncClient):
        access_a, org_id_a = await _create_org_and_get_tokens(client, "iso-findings-a")
        access_b, org_id_b = await _create_org_and_get_tokens(client, "iso-findings-b")

        fake_scan_id = uuid.uuid4()
        resp = await client.get(
            f"/api/v1/scans/{fake_scan_id}/findings?org_id={org_id_b}",
            headers=auth_headers(access_a),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cross_tenant_cancel_returns_404(self, client: AsyncClient):
        access_a, org_id_a = await _create_org_and_get_tokens(client, "iso-cancel-a")
        access_b, org_id_b = await _create_org_and_get_tokens(client, "iso-cancel-b")

        fake_scan_id = uuid.uuid4()
        resp = await client.post(
            f"/api/v1/scans/{fake_scan_id}/cancel?org_id={org_id_b}",
            headers=auth_headers(access_a),
        )
        assert resp.status_code == 404


class TestScanRBAC:
    @pytest.mark.asyncio
    async def test_auditor_cannot_create_scan(self, client: AsyncClient):
        """Auditor role has assessment:read but not assessment:write."""
        access_admin, org_id = await _create_org_and_get_tokens(client, "rbac-admin")

        await register_user(client, email="rbac_auditor@example.com")
        tokens_auditor = await login_user(client, email="rbac_auditor@example.com")
        access_auditor = tokens_auditor["access_token"]

        resp = await client.post(
            f"/api/v1/orgs/{org_id}/members/invite",
            json={"email": "rbac_auditor@example.com", "role": "auditor"},
            headers=auth_headers(access_admin),
        )
        assert resp.status_code == 201

        resp = await client.post(
            f"/api/v1/orgs/{org_id}/scans",
            json={"target_domain": "example.com"},
            headers=auth_headers(access_auditor),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_auditor_can_read_scans(self, client: AsyncClient):
        """Auditor has assessment:read."""
        access_admin, org_id = await _create_org_and_get_tokens(client, "rbac-read")

        await register_user(client, email="rbac_read_auditor@example.com")
        tokens_auditor = await login_user(client, email="rbac_read_auditor@example.com")
        access_auditor = tokens_auditor["access_token"]

        resp = await client.post(
            f"/api/v1/orgs/{org_id}/members/invite",
            json={"email": "rbac_read_auditor@example.com", "role": "auditor"},
            headers=auth_headers(access_admin),
        )
        assert resp.status_code == 201

        resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans",
            headers=auth_headers(access_auditor),
        )
        assert resp.status_code == 200


class TestScanPersistence:
    @pytest.mark.asyncio
    async def test_completed_scan_stored_in_db(self, client: AsyncClient):
        """Create a scan with mocked engines + inline dispatch, then retrieve it — data persists in DB."""
        access, org_id = await _create_org_and_get_tokens(client, "persist")

        async def _no_findings(self, domain):
            return []

        with _mock_scan_dispatch_inline(), \
             patch("app.services.scan_service.ScanService._run_engines", new=_no_findings), \
             patch("app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()):
            create_resp = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers=auth_headers(access),
            )

        assert create_resp.status_code == 201
        scan_id = create_resp.json()["id"]
        # Inline dispatch completes the scan synchronously
        assert create_resp.json()["status"] == "completed"

        get_resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans/{scan_id}",
            headers=auth_headers(access),
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == scan_id
        assert get_resp.json()["target_domain"] == "example.com"
        assert get_resp.json()["status"] == "completed"

    @pytest.mark.asyncio
    async def test_queued_scan_has_queued_status(self, client: AsyncClient):
        """Without inline dispatch (task not run), scan stays QUEUED."""
        access, org_id = await _create_org_and_get_tokens(client, "queued")

        async def _noop_dispatch(self, scan):
            return None

        with patch("app.services.scan_service.ScanService._dispatch_task", new=_noop_dispatch), \
             patch("app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()):
            resp = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers=auth_headers(access),
            )

        assert resp.status_code == 201
        assert resp.json()["status"] == "queued"

    @pytest.mark.asyncio
    async def test_scan_response_has_progress_fields(self, client: AsyncClient):
        """ScanResponse includes progress_pct and current_engine."""
        access, org_id = await _create_org_and_get_tokens(client, "progress")

        with _mock_scan_service_ok():
            resp = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers=auth_headers(access),
            )

        assert resp.status_code == 201
        body = resp.json()
        assert "progress_pct" in body
        assert "current_engine" in body


class TestScanCancel:
    @pytest.mark.asyncio
    async def test_cancel_nonexistent_scan_404(self, client: AsyncClient):
        access, org_id = await _create_org_and_get_tokens(client, "cancel-404")
        resp = await client.post(
            f"/api/v1/orgs/{org_id}/scans/{uuid.uuid4()}/cancel",
            headers=auth_headers(access),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cancel_completed_scan_conflict(self, client: AsyncClient):
        """Completed scan cannot be cancelled retroactively — 409 Conflict."""
        access, org_id = await _create_org_and_get_tokens(client, "cancel-completed")

        async def _no_findings(self, domain):
            return []

        with _mock_scan_dispatch_inline(), \
             patch("app.services.scan_service.ScanService._run_engines", new=_no_findings), \
             patch("app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()):
            create_resp = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers=auth_headers(access),
            )
        assert create_resp.status_code == 201
        scan_id = create_resp.json()["id"]

        cancel_resp = await client.post(
            f"/api/v1/orgs/{org_id}/scans/{scan_id}/cancel",
            headers=auth_headers(access),
        )
        assert cancel_resp.status_code == 409

    @pytest.mark.asyncio
    async def test_cancel_queued_scan_succeeds(self, client: AsyncClient):
        """Cancelling a QUEUED scan sets status to cancelled immediately."""
        access, org_id = await _create_org_and_get_tokens(client, "cancel-queued")

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
        assert create_resp.json()["status"] == "queued"
        scan_id = create_resp.json()["id"]

        cancel_resp = await client.post(
            f"/api/v1/orgs/{org_id}/scans/{scan_id}/cancel",
            headers=auth_headers(access),
        )
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_already_cancelled_scan_conflict(self, client: AsyncClient):
        """Cancelling an already-cancelled scan → 409."""
        access, org_id = await _create_org_and_get_tokens(client, "cancel-twice")

        async def _noop_dispatch(self, scan):
            return None

        with patch("app.services.scan_service.ScanService._dispatch_task", new=_noop_dispatch), \
             patch("app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()):
            create_resp = await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com"},
                headers=auth_headers(access),
            )
        scan_id = create_resp.json()["id"]

        # First cancel
        cancel1 = await client.post(
            f"/api/v1/orgs/{org_id}/scans/{scan_id}/cancel",
            headers=auth_headers(access),
        )
        assert cancel1.status_code == 200

        # Second cancel
        cancel2 = await client.post(
            f"/api/v1/orgs/{org_id}/scans/{scan_id}/cancel",
            headers=auth_headers(access),
        )
        assert cancel2.status_code == 409
