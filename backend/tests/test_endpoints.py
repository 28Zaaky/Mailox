"""
Tests for new endpoints:
  - DELETE /orgs/{org_id}/scans/{scan_id}
  - DELETE /orgs/{org_id}/members/{user_id}
  - GET    /orgs/{org_id}/stats
  - GET    /orgs/{org_id}/scans/{scan_id}/assets
"""
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from tests.conftest import auth_headers, login_user, register_user, verify_domain


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _setup(client: AsyncClient, suffix: str) -> tuple[str, str]:
    """Register + login + create org. Returns (access_token, org_id)."""
    email = f"p7_{suffix}@example.com"
    await register_user(client, email=email)
    tokens = await login_user(client, email=email)
    access = tokens["access_token"]
    slug = f"p7org{suffix}".replace("_", "")[:50]
    resp = await client.post(
        "/api/v1/orgs",
        json={"name": f"Phase7 Org {suffix}", "slug": slug},
        headers=auth_headers(access),
    )
    assert resp.status_code == 201
    org_id = resp.json()["id"]
    # SaaS edition: scans are only accepted on a domain the org has verified
    await verify_domain(org_id, "example.com")
    return access, org_id


def _mock_scan_ok():
    from app.db.models.scan import Scan, ScanStatus

    async def _fake(self, org_id, target_domain, created_by, idempotency_key=None,
                    project_id=None, profile_id=None, skip_domain_verification=False):
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
        scan.progress_pct = 100
        scan.current_engine = None
        scan.idempotency_key = idempotency_key
        return scan

    return patch(
        "app.services.scan_service.ScanService.create_and_run_scan",
        new=_fake,
    )


def _mock_inline():
    from app.db.models.scan import Scan, ScanStatus

    async def _inline(self, scan: Scan):
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


async def _create_real_scan(client: AsyncClient, access: str, org_id: str) -> str:
    """Create a real COMPLETED scan in the DB, return scan_id."""
    with _mock_inline(), patch(
        "app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()
    ), patch(
        "app.services.scan_service.ScanService._run_engines", new=AsyncMock(return_value=[])
    ):
        resp = await client.post(
            f"/api/v1/orgs/{org_id}/scans",
            json={"target_domain": "example.com"},
            headers=auth_headers(access),
        )
    assert resp.status_code == 201, f"scan create failed: {resp.text}"
    return resp.json()["id"]


# ── DELETE /orgs/{org_id}/scans/{scan_id} ─────────────────────────────────────


class TestDeleteScan:
    @pytest.mark.asyncio
    async def test_delete_completed_scan_returns_204(self, client: AsyncClient):
        access, org_id = await _setup(client, "del1")
        scan_id = await _create_real_scan(client, access, org_id)

        resp = await client.delete(
            f"/api/v1/orgs/{org_id}/scans/{scan_id}",
            headers=auth_headers(access),
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_nonexistent_scan_404(self, client: AsyncClient):
        access, org_id = await _setup(client, "del2")

        resp = await client.delete(
            f"/api/v1/orgs/{org_id}/scans/{uuid.uuid4()}",
            headers=auth_headers(access),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_scan_tenant_isolation(self, client: AsyncClient):
        """User from org B cannot delete a scan from org A."""
        access_a, org_id_a = await _setup(client, "del_ta")
        access_b, org_id_b = await _setup(client, "del_tb")
        scan_id = await _create_real_scan(client, access_a, org_id_a)

        resp = await client.delete(
            f"/api/v1/orgs/{org_id_a}/scans/{scan_id}",
            headers=auth_headers(access_b),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_scan_unauthenticated(self, client: AsyncClient):
        resp = await client.delete(
            f"/api/v1/orgs/{uuid.uuid4()}/scans/{uuid.uuid4()}"
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_delete_running_scan_409(self, client: AsyncClient, db):
        """DELETE on a scan whose status is RUNNING should return 409."""
        from app.db.models.scan import Scan, ScanStatus
        from sqlalchemy import update as _update

        access, org_id = await _setup(client, "delrun")
        scan_id = await _create_real_scan(client, access, org_id)

        await db.execute(
            _update(Scan)
            .where(Scan.id == uuid.UUID(scan_id))
            .values(status=ScanStatus.RUNNING)
        )
        await db.flush()

        resp = await client.delete(
            f"/api/v1/orgs/{org_id}/scans/{scan_id}",
            headers=auth_headers(access),
        )
        assert resp.status_code == 409


# ── DELETE /orgs/{org_id}/members/{user_id} ───────────────────────────────────


class TestDeleteMember:
    @pytest.mark.asyncio
    async def test_remove_member_204(self, client: AsyncClient):
        access_admin, org_id = await _setup(client, "rm1a")

        # Add a second member
        email_b = "rm1b@example.com"
        await register_user(client, email=email_b)
        tokens_b = await login_user(client, email=email_b)
        user_b_id = (
            await client.get("/api/v1/auth/me", headers=auth_headers(tokens_b["access_token"]))
        ).json()["id"]

        inv_resp = await client.post(
            f"/api/v1/orgs/{org_id}/members/invite",
            json={"email": email_b, "role": "analyst"},
            headers=auth_headers(access_admin),
        )
        assert inv_resp.status_code == 201

        resp = await client.delete(
            f"/api/v1/orgs/{org_id}/members/{user_b_id}",
            headers=auth_headers(access_admin),
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_remove_member_nonexistent_404(self, client: AsyncClient):
        access, org_id = await _setup(client, "rm2")

        resp = await client.delete(
            f"/api/v1/orgs/{org_id}/members/{uuid.uuid4()}",
            headers=auth_headers(access),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_remove_last_admin_409(self, client: AsyncClient):
        """Cannot remove yourself if you are the only admin."""
        access, org_id = await _setup(client, "rm3")
        me_resp = await client.get("/api/v1/auth/me", headers=auth_headers(access))
        my_id = me_resp.json()["id"]

        resp = await client.delete(
            f"/api/v1/orgs/{org_id}/members/{my_id}",
            headers=auth_headers(access),
        )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_remove_member_tenant_isolation(self, client: AsyncClient):
        """User from org B cannot remove a member from org A."""
        access_a, org_id_a = await _setup(client, "rm_ta")
        access_b, org_id_b = await _setup(client, "rm_tb")
        me_a = (
            await client.get("/api/v1/auth/me", headers=auth_headers(access_a))
        ).json()["id"]

        resp = await client.delete(
            f"/api/v1/orgs/{org_id_a}/members/{me_a}",
            headers=auth_headers(access_b),
        )
        assert resp.status_code == 404


# ── GET /orgs/{org_id}/stats ──────────────────────────────────────────────────


class TestOrgStats:
    @pytest.mark.asyncio
    async def test_stats_empty_org(self, client: AsyncClient):
        access, org_id = await _setup(client, "st1")

        resp = await client.get(
            f"/api/v1/orgs/{org_id}/stats",
            headers=auth_headers(access),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_scans"] == 0
        assert body["active_scans"] == 0
        assert body["open_critical"] == 0
        assert body["open_high"] == 0
        assert body["latest_scan_id"] is None
        assert body["latest_risk_score"] is None

    @pytest.mark.asyncio
    async def test_stats_with_scan(self, client: AsyncClient):
        access, org_id = await _setup(client, "st2")
        await _create_real_scan(client, access, org_id)

        resp = await client.get(
            f"/api/v1/orgs/{org_id}/stats",
            headers=auth_headers(access),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_scans"] >= 1

    @pytest.mark.asyncio
    async def test_stats_tenant_isolation(self, client: AsyncClient):
        """User from org B cannot see stats of org A."""
        access_a, org_id_a = await _setup(client, "st_ta")
        access_b, _ = await _setup(client, "st_tb")

        resp = await client.get(
            f"/api/v1/orgs/{org_id_a}/stats",
            headers=auth_headers(access_b),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_stats_unauthenticated(self, client: AsyncClient):
        resp = await client.get(f"/api/v1/orgs/{uuid.uuid4()}/stats")
        assert resp.status_code == 401


# ── GET /orgs/{org_id}/scans/{scan_id}/assets ─────────────────────────────────


class TestScanAssets:
    @pytest.mark.asyncio
    async def test_assets_empty_scan(self, client: AsyncClient):
        access, org_id = await _setup(client, "ast1")
        scan_id = await _create_real_scan(client, access, org_id)

        resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans/{scan_id}/assets",
            headers=auth_headers(access),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["mx_records"] == []
        assert body["webmail_hosts"] == []
        assert body["smtp_hosts"] == []

    @pytest.mark.asyncio
    async def test_assets_nonexistent_scan_404(self, client: AsyncClient):
        access, org_id = await _setup(client, "ast2")

        resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans/{uuid.uuid4()}/assets",
            headers=auth_headers(access),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_assets_tenant_isolation(self, client: AsyncClient):
        """User from org B cannot access assets of org A's scan."""
        access_a, org_id_a = await _setup(client, "ast_ta")
        access_b, _ = await _setup(client, "ast_tb")
        scan_id = await _create_real_scan(client, access_a, org_id_a)

        resp = await client.get(
            f"/api/v1/orgs/{org_id_a}/scans/{scan_id}/assets",
            headers=auth_headers(access_b),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_assets_unauthenticated(self, client: AsyncClient):
        resp = await client.get(
            f"/api/v1/orgs/{uuid.uuid4()}/scans/{uuid.uuid4()}/assets"
        )
        assert resp.status_code == 401
