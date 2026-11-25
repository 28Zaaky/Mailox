"""
Regression tests for functional fixes:
  1. assets/scope endpoints use permissions that exist in ROLE_PERMISSIONS,
     record the acting User (not the OrganizationMember) as authorized_by,
     and work for a platform admin (RequirePermission returns None for them).
  2. GET /scans/engine-stats is not shadowed by GET /scans/{scan_id}; list
     pagination is bounded.
  3. Canonical-finding item routes are reachable (no longer shadowed by the
     scan-findings router at /findings/{finding_id}).
  + SSE ticket redemption, failed-login counter persistence, smtp_discovery
    banner handling.
"""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select, update

from app.db.models.organization import OrganizationMember, OrgRole
from app.db.models.user import User
from tests.conftest import TEST_PASSWORD, auth_headers, login_user, register_user, verify_domain


async def _user_with_org(client: AsyncClient, prefix: str) -> tuple[str, str, str]:
    """Register + login + create org. Returns (access_token, org_id, user_id)."""
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"
    await register_user(client, email=email)
    token = (await login_user(client, email=email))["access_token"]
    resp = await client.post(
        "/api/v1/orgs",
        json={"name": f"{prefix} org", "slug": f"{prefix}-{uuid.uuid4().hex[:8]}"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 201, resp.text
    me = await client.get("/api/v1/auth/me", headers=auth_headers(token))
    return token, resp.json()["id"], me.json()["id"]


async def _add_member(client, db, org_id: str, role: OrgRole) -> str:
    email = f"{role.value}-{uuid.uuid4().hex[:8]}@example.com"
    user = await register_user(client, email=email)
    token = (await login_user(client, email=email))["access_token"]
    user_id = (await client.get("/api/v1/auth/me", headers=auth_headers(token))).json()["id"]
    db.add(OrganizationMember(org_id=uuid.UUID(org_id), user_id=uuid.UUID(user_id), role=role))
    await db.flush()
    return token


async def _project(client, token, org_id) -> str:
    resp = await client.post(
        f"/api/v1/orgs/{org_id}/projects",
        json={"name": "Scope project"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ── 1. Assets / scope RBAC ────────────────────────────────────────────────────


class TestAssetsRBAC:
    async def test_org_admin_full_scope_flow(self, client: AsyncClient):
        token, org_id, user_id = await _user_with_org(client, "assets-admin")
        hdrs = auth_headers(token)
        project_id = await _project(client, token, org_id)

        resp = await client.post(
            f"/api/v1/orgs/{org_id}/projects/{project_id}/scope",
            json={"asset_type": "domain", "value": "scope.example.com"},
            headers=hdrs,
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        # authorized_by is the acting user, not the OrganizationMember row id
        assert body["authorized_by"] == user_id
        assert body["asset"]["metadata"] == {}
        asset_id = body["asset_id"]

        resp = await client.get(f"/api/v1/orgs/{org_id}/projects/{project_id}/scope", headers=hdrs)
        assert resp.status_code == 200
        assert [p["asset_id"] for p in resp.json()] == [asset_id]

        resp = await client.get(f"/api/v1/orgs/{org_id}/assets", headers=hdrs)
        assert resp.status_code == 200
        assert resp.json()[0]["metadata"] == {}

        resp = await client.get(f"/api/v1/orgs/{org_id}/assets/{asset_id}", headers=hdrs)
        assert resp.status_code == 200

        resp = await client.delete(
            f"/api/v1/orgs/{org_id}/projects/{project_id}/scope/{asset_id}", headers=hdrs
        )
        assert resp.status_code == 204

    async def test_auditor_reads_but_cannot_change_scope(self, client: AsyncClient, db):
        admin_token, org_id, _ = await _user_with_org(client, "assets-aud")
        project_id = await _project(client, admin_token, org_id)
        auditor_token = await _add_member(client, db, org_id, OrgRole.AUDITOR)
        hdrs = auth_headers(auditor_token)

        assert (await client.get(f"/api/v1/orgs/{org_id}/assets", headers=hdrs)).status_code == 200
        resp = await client.get(f"/api/v1/orgs/{org_id}/projects/{project_id}/scope", headers=hdrs)
        assert resp.status_code == 200
        resp = await client.post(
            f"/api/v1/orgs/{org_id}/projects/{project_id}/scope",
            json={"asset_type": "domain", "value": "nope.example.com"},
            headers=hdrs,
        )
        assert resp.status_code == 403

    async def test_pentester_cannot_change_scope(self, client: AsyncClient, db):
        admin_token, org_id, _ = await _user_with_org(client, "assets-pt")
        project_id = await _project(client, admin_token, org_id)
        pt_token = await _add_member(client, db, org_id, OrgRole.PENTESTER)
        resp = await client.post(
            f"/api/v1/orgs/{org_id}/projects/{project_id}/scope",
            json={"asset_type": "domain", "value": "nope.example.com"},
            headers=auth_headers(pt_token),
        )
        assert resp.status_code == 403

    async def test_platform_admin_add_scope(self, client: AsyncClient, db, monkeypatch):
        """RequirePermission returns None for a platform admin; the endpoint must
        still have a User for authorized_by (used to raise AttributeError).

        Self-hosted only: in SaaS the platform admin never sees customer orgs."""
        from app.core.config import settings
        monkeypatch.setattr(settings, "MAILOX_EDITION", "selfhosted")
        admin_token, org_id, _ = await _user_with_org(client, "assets-pa-owner")
        project_id = await _project(client, admin_token, org_id)

        email = f"padmin-{uuid.uuid4().hex[:8]}@example.com"
        await register_user(client, email=email)
        await db.execute(update(User).where(User.email == email).values(is_platform_admin=True))
        await db.flush()
        pa_token = (await login_user(client, email=email))["access_token"]
        pa_id = (await client.get("/api/v1/auth/me", headers=auth_headers(pa_token))).json()["id"]

        resp = await client.post(
            f"/api/v1/orgs/{org_id}/projects/{project_id}/scope",
            json={"asset_type": "domain", "value": "pa.example.com"},
            headers=auth_headers(pa_token),
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["authorized_by"] == pa_id


# ── 2. Scans routing ──────────────────────────────────────────────────────────


class TestScansRouting:
    async def test_engine_stats_not_shadowed(self, client: AsyncClient):
        token, org_id, _ = await _user_with_org(client, "estats")
        resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans/engine-stats",
            params={"engine": "dns_auth"},
            headers=auth_headers(token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["engine"] == "dns_auth"
        assert resp.json()["run_count"] == 0

    @pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 101}, {"offset": -1}])
    async def test_list_scans_pagination_bounded(self, client: AsyncClient, params):
        token, org_id, _ = await _user_with_org(client, "pagin")
        resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans", params=params, headers=auth_headers(token)
        )
        assert resp.status_code == 422

    async def test_list_scans_pagination_valid(self, client: AsyncClient):
        token, org_id, _ = await _user_with_org(client, "pagin-ok")
        resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans",
            params={"limit": 100, "offset": 0},
            headers=auth_headers(token),
        )
        assert resp.status_code == 200


# ── 3. Findings routing ───────────────────────────────────────────────────────


class TestFindingsRouting:
    def test_no_duplicate_method_path_pairs(self):
        """No two routes may share (method, path): the later one is unreachable."""
        from fastapi.routing import APIRoute
        from app.main import app

        seen: dict[tuple[str, str], str] = {}
        dupes = []
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            for method in route.methods:
                key = (method, route.path)
                if key in seen:
                    dupes.append((key, seen[key], route.name))
                seen[key] = route.name
        assert dupes == []

    def test_canonical_item_routes_registered(self):
        from app.main import app

        paths = {(m, r.path) for r in app.routes for m in getattr(r, "methods", ())}
        base = "/api/v1/orgs/{org_id}/canonical-findings/{finding_id}"
        assert ("GET", base) in paths
        assert ("PATCH", base) in paths
        assert ("GET", base + "/history") in paths
        # Scan-finding routes used by the frontend stay where they were
        assert ("GET", "/api/v1/orgs/{org_id}/findings/{finding_id}") in paths
        assert ("PATCH", "/api/v1/orgs/{org_id}/findings/{finding_id}") in paths
        # Backward-compatible history path kept
        assert ("GET", "/api/v1/orgs/{org_id}/findings/{finding_id}/history") in paths

    async def test_canonical_get_reaches_canonical_handler(self, client: AsyncClient):
        token, org_id, _ = await _user_with_org(client, "canon")
        resp = await client.get(
            f"/api/v1/orgs/{org_id}/canonical-findings/{uuid.uuid4()}",
            headers=auth_headers(token),
        )
        assert resp.status_code == 404


# ── SSE ticket ────────────────────────────────────────────────────────────────


class TestSSETicket:
    async def test_ticket_redeemable_and_bound_to_scan(self, client: AsyncClient, db):
        token, org_id, _ = await _user_with_org(client, "sse-ticket")
        await verify_domain(org_id, "example.com")
        hdrs = auth_headers(token)
        with patch("app.services.scan_service.SSRFGuard.validate_domain_for_scan", new=AsyncMock()), \
             patch("app.worker.tasks.scan_task.delay", return_value=MagicMock(id="fake-task")):
            resp = await client.post(
                f"/api/v1/orgs/{org_id}/scans", json={"target_domain": "example.com"}, headers=hdrs
            )
        assert resp.status_code == 201, resp.text
        scan_id = resp.json()["id"]

        from app.api.v1.endpoints.scans import _get_user_for_sse

        async def _ticket():
            r = await client.post(f"/api/v1/orgs/{org_id}/scans/{scan_id}/stream-token", headers=hdrs)
            assert r.status_code == 200
            return r.json()["sse_token"]

        # decode_responses=True client returns str: must be accepted
        user = await _get_user_for_sse(uuid.UUID(org_id), uuid.UUID(scan_id), await _ticket(), db)
        assert user is not None

        # single use
        t = await _ticket()
        await _get_user_for_sse(uuid.UUID(org_id), uuid.UUID(scan_id), t, db)
        with pytest.raises(HTTPException) as exc:
            await _get_user_for_sse(uuid.UUID(org_id), uuid.UUID(scan_id), t, db)
        assert exc.value.status_code == 401

        # bound to its scan
        with pytest.raises(HTTPException) as exc:
            await _get_user_for_sse(uuid.UUID(org_id), uuid.uuid4(), await _ticket(), db)
        assert exc.value.status_code == 401


# ── Lockout counter survives the request rollback ────────────────────────────


class TestLockoutPersistence:
    async def test_failed_login_counter_survives_rollback(self, client: AsyncClient, db):
        """get_db() rolls back on any exception, including the 401 raised for a bad
        password. The failed-attempt counter must already be committed by then."""
        from app.services.auth_service import AuthService

        email = f"lock-persist-{uuid.uuid4().hex[:8]}@example.com"
        await register_user(client, email=email)

        with pytest.raises(HTTPException):
            await AuthService(db).login(email, "WrongPass999!", ip=None, user_agent=None)
        await db.rollback()  # what get_db() does on the 401

        attempts = (await db.execute(
            select(User.failed_login_attempts).where(User.email == email)
        )).scalar_one()
        assert attempts == 1


# ── smtp_discovery banner handling ───────────────────────────────────────────


class TestSMTPBannerFindings:
    def test_unrecognised_banner_does_not_crash(self):
        from app.engines.smtp_discovery import SMTPProbeResult, _findings_from_probe

        probe = SMTPProbeResult(
            host="mx.example.com", port=25, ip="203.0.113.10", connected=True,
            banner="220 mx.example.com ESMTP Postfix",
        )
        findings = _findings_from_probe(probe, "example.com")
        assert any(f.check_id == "SMTP-04" for f in findings)
