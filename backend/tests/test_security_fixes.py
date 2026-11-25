"""Regression tests for the security fixes:

1. Cross-tenant IDOR on scan creation (project_id / profile_id)
2. /auth/local-session: disabled by default, strict loopback only
3. PATCH /orgs/{id}/pentest-config + test-canary: org:write, schema, audit log
4. Webhook SSRF: async validation, full blocklist, DNS pinning, no error leak
5. /forgot-password: identical 204, atomic token consume, lockout reset
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import dns.resolver
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

from app.core.config import settings
from app.db.models.audit import AuditLog
from app.db.models.organization import OrganizationMember, OrgRole
from app.db.models.profile import AssessmentProfile
from app.db.models.project import Project
from app.db.models.user import User
from app.db.session import get_db
from app.main import app
from tests.conftest import auth_headers, login_user, register_user, verify_domain


def _email(tag: str) -> str:
    return f"{tag}-{uuid.uuid4().hex[:10]}@secfix-test.dev"


async def _user_with_org(client: AsyncClient, tag: str) -> tuple[str, str, str]:
    """Returns (email, access_token, org_id). A throwaway user is registered first so the
    tested user is never the instance's first account (which becomes platform admin)."""
    await register_user(client, email=_email("first"))
    email = _email(tag)
    await register_user(client, email=email)
    token = (await login_user(client, email=email))["access_token"]
    resp = await client.post(
        "/api/v1/orgs",
        json={"name": f"Org {tag}", "slug": f"secfix-{uuid.uuid4().hex[:10]}"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 201, resp.text
    return email, token, resp.json()["id"]


async def _noop_dispatch(self, scan):
    return None


# ── 1. Scan creation IDOR ────────────────────────────────────────────────────

class TestScanCreationIDOR:
    async def _two_tenants(self, client, db):
        _, token_a, org_a = await _user_with_org(client, "scan-a")
        _, token_b, org_b = await _user_with_org(client, "scan-b")
        now = datetime.now(timezone.utc)
        project_a = Project(
            id=uuid.uuid4(), org_id=uuid.UUID(org_a), name="A project",
            created_at=now, updated_at=now,
        )
        profile_a = AssessmentProfile(
            id=uuid.uuid4(), org_id=uuid.UUID(org_a), name="A profile",
            engines=["dns_auth"], config={}, created_at=now, is_builtin=False,
        )
        project_b = Project(
            id=uuid.uuid4(), org_id=uuid.UUID(org_b), name="B project",
            created_at=now, updated_at=now,
        )
        db.add_all([project_a, profile_a, project_b])
        await db.flush()
        # SaaS edition: org B owns the target, so only the reference checks decide
        await verify_domain(org_b, "example.com")
        return token_b, org_b, project_a, profile_a, project_b

    async def _post_scan(self, client, token, org_id, body):
        with patch("app.services.scan_service.ScanService._dispatch_task", new=_noop_dispatch), \
             patch("app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()):
            return await client.post(
                f"/api/v1/orgs/{org_id}/scans",
                json={"target_domain": "example.com", **body},
                headers=auth_headers(token),
            )

    async def test_foreign_project_id_is_404(self, client, db):
        token_b, org_b, project_a, _, _ = await self._two_tenants(client, db)
        resp = await self._post_scan(client, token_b, org_b, {"project_id": str(project_a.id)})
        assert resp.status_code == 404

    async def test_foreign_profile_id_is_404(self, client, db):
        token_b, org_b, _, profile_a, _ = await self._two_tenants(client, db)
        resp = await self._post_scan(client, token_b, org_b, {"profile_id": str(profile_a.id)})
        assert resp.status_code == 404

    async def test_unknown_project_id_is_404(self, client, db):
        token_b, org_b, _, _, _ = await self._two_tenants(client, db)
        resp = await self._post_scan(client, token_b, org_b, {"project_id": str(uuid.uuid4())})
        assert resp.status_code == 404

    async def test_own_project_id_is_accepted(self, client, db):
        token_b, org_b, _, _, project_b = await self._two_tenants(client, db)
        resp = await self._post_scan(client, token_b, org_b, {"project_id": str(project_b.id)})
        assert resp.status_code == 201, resp.text

    async def test_builtin_profile_is_accepted(self, client, db):
        token_b, org_b, _, _, _ = await self._two_tenants(client, db)
        builtin = AssessmentProfile(
            id=uuid.uuid4(), org_id=None, name="Builtin", engines=["dns_auth"], config={},
            created_at=datetime.now(timezone.utc), is_builtin=True,
        )
        db.add(builtin)
        await db.flush()
        resp = await self._post_scan(client, token_b, org_b, {"profile_id": str(builtin.id)})
        assert resp.status_code == 201, resp.text


# ── 2. /auth/local-session ───────────────────────────────────────────────────

def _client_from(db, host: str) -> AsyncClient:
    async def _override_get_db():
        yield db

    app.dependency_overrides[get_db] = _override_get_db
    return AsyncClient(transport=ASGITransport(app=app, client=(host, 40000)), base_url="https://test")


class TestLocalSession:
    # /auth/local-session is a self-hosted feature: the SaaS edition (the default)
    # always answers 404, see test_saas_never_serves_local_session.
    @pytest.fixture(autouse=True)
    def _selfhosted(self, monkeypatch):
        monkeypatch.setattr(settings, "MAILOX_EDITION", "selfhosted")

    async def test_disabled_by_default_returns_404(self, client, monkeypatch):
        assert settings.LOCAL_SESSION_ENABLED is False  # secure default
        resp = await client.post("/api/v1/auth/local-session")
        assert resp.status_code == 404

    async def test_saas_never_serves_local_session(self, db, monkeypatch):
        monkeypatch.setattr(settings, "MAILOX_EDITION", "saas")
        monkeypatch.setattr(settings, "LOCAL_SESSION_ENABLED", True)
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 0)
        async with _client_from(db, "127.0.0.1") as c:
            resp = await c.post("/api/v1/auth/local-session")
        app.dependency_overrides.clear()
        assert resp.status_code == 404

    async def test_loopback_accepted_when_enabled(self, db, monkeypatch):
        monkeypatch.setattr(settings, "LOCAL_SESSION_ENABLED", True)
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 0)
        async with _client_from(db, "127.0.0.1") as c:
            resp = await c.post("/api/v1/auth/local-session")
        app.dependency_overrides.clear()
        assert resp.status_code == 200, resp.text
        assert resp.json()["access_token"]

    @pytest.mark.parametrize("host", ["192.168.1.10", "172.18.0.1", "10.0.0.5", "8.8.8.8", "testclient"])
    async def test_non_loopback_rejected(self, db, monkeypatch, host):
        monkeypatch.setattr(settings, "LOCAL_SESSION_ENABLED", True)
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 0)
        async with _client_from(db, host) as c:
            resp = await c.post("/api/v1/auth/local-session")
        app.dependency_overrides.clear()
        assert resp.status_code == 403

    async def test_forwarded_header_without_trusted_proxy_rejected(self, db, monkeypatch):
        """Loopback peer but X-Forwarded-For present and TRUSTED_PROXY_COUNT=0: an unknown
        proxy sits in front (e.g. a host nginx forwarding remote traffic) -> refuse."""
        monkeypatch.setattr(settings, "LOCAL_SESSION_ENABLED", True)
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 0)
        async with _client_from(db, "127.0.0.1") as c:
            resp = await c.post(
                "/api/v1/auth/local-session", headers={"X-Forwarded-For": "203.0.113.9"}
            )
        app.dependency_overrides.clear()
        assert resp.status_code == 403

    async def test_trusted_proxy_docker_gateway_rejected(self, db, monkeypatch):
        """Bundled Docker stack: nginx (172.18.0.3) forwards the bridge gateway as client."""
        monkeypatch.setattr(settings, "LOCAL_SESSION_ENABLED", True)
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 1)
        async with _client_from(db, "172.18.0.3") as c:
            resp = await c.post(
                "/api/v1/auth/local-session", headers={"X-Forwarded-For": "172.18.0.1"}
            )
        app.dependency_overrides.clear()
        assert resp.status_code == 403

    async def test_trusted_proxy_spoofed_xff_rejected(self, db, monkeypatch):
        """Attacker prepends 127.0.0.1; the proxy appends the real address -> rightmost wins."""
        monkeypatch.setattr(settings, "LOCAL_SESSION_ENABLED", True)
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 1)
        async with _client_from(db, "127.0.0.1") as c:
            resp = await c.post(
                "/api/v1/auth/local-session", headers={"X-Forwarded-For": "127.0.0.1, 198.51.100.7"}
            )
        app.dependency_overrides.clear()
        assert resp.status_code == 403

    async def test_trusted_proxy_loopback_client_accepted(self, db, monkeypatch):
        monkeypatch.setattr(settings, "LOCAL_SESSION_ENABLED", True)
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 1)
        async with _client_from(db, "127.0.0.1") as c:
            resp = await c.post(
                "/api/v1/auth/local-session", headers={"X-Forwarded-For": "127.0.0.1"}
            )
        app.dependency_overrides.clear()
        assert resp.status_code == 200, resp.text

    async def test_local_session_reuses_instance_owner(self, db, monkeypatch):
        # Current design (AuthService.local_session): the loopback session belongs to
        # the instance owner. ALLOW_REGISTRATION no longer gates it (the flag is not
        # read anywhere). Invariant kept here: when accounts exist, no new account is
        # created and only the earliest active account becomes platform admin.
        monkeypatch.setattr(settings, "LOCAL_SESSION_ENABLED", True)
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 0)
        await db.execute(update(User).values(is_platform_admin=False))
        now = datetime.now(timezone.utc)
        owner = User(
            id=uuid.uuid4(), email=_email("ls-owner"), password_hash="x",
            created_at=now - timedelta(days=3650),
        )
        other = User(
            id=uuid.uuid4(), email=_email("ls-other"), password_hash="x",
            created_at=now - timedelta(days=3649),
        )
        db.add_all([owner, other])
        await db.flush()
        users_before = len((await db.execute(select(User.id))).all())
        async with _client_from(db, "127.0.0.1") as c:
            resp = await c.post("/api/v1/auth/local-session")
        app.dependency_overrides.clear()
        assert resp.status_code == 200, resp.text
        assert len((await db.execute(select(User.id))).all()) == users_before
        admins = (await db.execute(
            select(User.id).where(User.is_platform_admin == True)  # noqa: E712
        )).scalars().all()
        assert admins == [owner.id]


# ── 3. pentest-config RBAC / schema / audit ──────────────────────────────────

class TestPentestConfig:
    async def _org_with_auditor(self, client, db):
        _, owner_token, org_id = await _user_with_org(client, "pc-owner")
        auditor_email = _email("pc-auditor")
        await register_user(client, email=auditor_email)
        auditor = (await db.execute(select(User).where(User.email == auditor_email))).scalar_one()
        db.add(OrganizationMember(
            id=uuid.uuid4(), org_id=uuid.UUID(org_id), user_id=auditor.id,
            role=OrgRole.AUDITOR, is_active=True,
        ))
        await db.flush()
        auditor_token = (await login_user(client, email=auditor_email))["access_token"]
        return owner_token, auditor_token, org_id

    async def test_auditor_patch_forbidden(self, client, db):
        _, auditor_token, org_id = await self._org_with_auditor(client, db)
        resp = await client.patch(
            f"/api/v1/orgs/{org_id}/pentest-config",
            json={"cred_probe_enabled": True},
            headers=auth_headers(auditor_token),
        )
        assert resp.status_code == 403

    async def test_auditor_test_canary_forbidden(self, client, db):
        _, auditor_token, org_id = await self._org_with_auditor(client, db)
        resp = await client.post(
            f"/api/v1/orgs/{org_id}/pentest-config/test-canary",
            headers=auth_headers(auditor_token),
        )
        assert resp.status_code == 403

    async def test_non_member_patch_404(self, client, db):
        _, _, org_id = await self._org_with_auditor(client, db)
        _, other_token, _ = await _user_with_org(client, "pc-other")
        resp = await client.patch(
            f"/api/v1/orgs/{org_id}/pentest-config",
            json={"cred_probe_enabled": True},
            headers=auth_headers(other_token),
        )
        assert resp.status_code == 404

    async def test_owner_patch_ok_and_audited(self, client, db):
        owner_token, _, org_id = await self._org_with_auditor(client, db)
        resp = await client.patch(
            f"/api/v1/orgs/{org_id}/pentest-config",
            json={"web_active_probe_enabled": True, "canary_email": "canary@example.com"},
            headers=auth_headers(owner_token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {
            "cred_probe_enabled": False,
            "web_active_probe_enabled": True,
            "canary_email": "canary@example.com",
        }
        log = (await db.execute(
            select(AuditLog).where(
                AuditLog.org_id == uuid.UUID(org_id),
                AuditLog.action == "org.pentest_config.update",
            )
        )).scalar_one()
        assert log.details["changes"]["web_active_probe_enabled"] == {"from": False, "to": True}

    @pytest.mark.parametrize("body", [
        {"unknown_key": 1},
        {"cred_probe_enabled": "yes"},
        {"canary_email": "not-an-email"},
        {"canary_email": "a" * 250 + "@x.io"},
    ])
    async def test_invalid_body_rejected(self, client, db, body):
        owner_token, _, org_id = await self._org_with_auditor(client, db)
        resp = await client.patch(
            f"/api/v1/orgs/{org_id}/pentest-config",
            json=body,
            headers=auth_headers(owner_token),
        )
        assert resp.status_code == 422

    async def test_platform_admin_keeps_full_rights(self, client, db, monkeypatch):
        # Self-hosted: the platform admin owns the install and sees every org
        monkeypatch.setattr(settings, "MAILOX_EDITION", "selfhosted")
        _, _, org_id = await self._org_with_auditor(client, db)
        admin_email = _email("pc-admin")
        await register_user(client, email=admin_email)
        await db.execute(update(User).where(User.email == admin_email).values(is_platform_admin=True))
        await db.flush()
        admin_token = (await login_user(client, email=admin_email))["access_token"]
        resp = await client.patch(
            f"/api/v1/orgs/{org_id}/pentest-config",
            json={"cred_probe_enabled": True},
            headers=auth_headers(admin_token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["cred_probe_enabled"] is True

    async def test_saas_platform_admin_cannot_reach_customer_org(self, client, db):
        # SaaS: the platform admin manages accounts but never sees customer orgs
        assert settings.IS_SAAS
        _, _, org_id = await self._org_with_auditor(client, db)
        admin_email = _email("pc-saas-admin")
        await register_user(client, email=admin_email)
        await db.execute(update(User).where(User.email == admin_email).values(is_platform_admin=True))
        await db.flush()
        admin_token = (await login_user(client, email=admin_email))["access_token"]
        resp = await client.patch(
            f"/api/v1/orgs/{org_id}/pentest-config",
            json={"cred_probe_enabled": True},
            headers=auth_headers(admin_token),
        )
        assert resp.status_code == 404


# ── 4. Webhook SSRF ──────────────────────────────────────────────────────────

class _RData:
    def __init__(self, ip: str) -> None:
        self._ip = ip

    def __str__(self) -> str:
        return self._ip


def _fake_dns(*a_answers: list[str]):
    """Patch dnspython: each A query pops the next answer list; AAAA -> NoAnswer."""
    queue = list(a_answers)

    async def _resolve(self, qname, rdtype="A", *args, **kwargs):
        if rdtype != "A":
            raise dns.resolver.NoAnswer()
        ips = queue.pop(0) if len(queue) > 1 else queue[0]
        return [_RData(ip) for ip in ips]

    return patch("dns.asyncresolver.Resolver.resolve", new=_resolve)


class TestWebhookSSRF:
    @pytest.mark.parametrize("url", [
        "http://0.0.0.0/hook",
        "http://[::]/hook",
        "http://224.0.0.1/hook",
        "http://127.0.0.1:6379/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:10.0.0.1]/",
        "http://localhost/hook",
        "http://user:pw@example.com/hook",
        "ftp://example.com/hook",
    ])
    async def test_blocked_literals(self, url):
        from app.worker.webhook_dispatch import is_safe_webhook_url

        safe, _ = await is_safe_webhook_url(url)
        assert safe is False

    async def test_hostname_resolving_to_private_ip_blocked(self):
        from app.worker.webhook_dispatch import is_safe_webhook_url

        with _fake_dns(["10.1.2.3"]):
            safe, reason = await is_safe_webhook_url("https://hooks.attacker.example/x")
        assert safe is False
        assert "10.1.2.3" in reason

    async def test_create_webhook_to_private_host_rejected(self, client):
        _, token, org_id = await _user_with_org(client, "wh")
        with _fake_dns(["192.168.0.10"]):
            resp = await client.post(
                f"/api/v1/orgs/{org_id}/webhooks",
                json={"url": "https://hooks.attacker.example/x", "events": ["scan.completed"]},
                headers=auth_headers(token),
            )
        assert resp.status_code == 422

    async def test_dns_rebinding_blocked_at_connect(self):
        """Pre-check sees a public IP, the pinned transport re-resolves at connect time and
        gets a private one: the connection must never be attempted."""
        from app.engines.ssrf_guard import SSRFGuardError
        from app.worker.webhook_dispatch import post_webhook

        connect = AsyncMock()
        with _fake_dns(["93.184.216.34"], ["127.0.0.1"]), \
             patch("httpcore._backends.auto.AutoBackend.connect_tcp", new=connect):
            with pytest.raises(SSRFGuardError):
                await post_webhook("http://rebind.attacker.example/x", "{}", {})
        connect.assert_not_called()

    async def test_connection_goes_to_validated_ip(self):
        from app.worker.webhook_dispatch import post_webhook

        seen: list[str] = []

        async def _fake_connect(self, host, port, **kw):
            seen.append(host)
            raise ConnectionRefusedError("stop here")

        with _fake_dns(["93.184.216.34"]), \
             patch("httpcore._backends.auto.AutoBackend.connect_tcp", new=_fake_connect):
            with pytest.raises(Exception):
                await post_webhook("http://hooks.example.org/x", "{}", {})
        assert seen == ["93.184.216.34"]

    async def test_test_endpoint_does_not_leak_exception_text(self, client, db):
        from app.db.models.webhook import WebhookConfig

        _, token, org_id = await _user_with_org(client, "wh-test")
        wh = WebhookConfig(
            id=uuid.uuid4(), org_id=uuid.UUID(org_id), url="https://hooks.example.org/x",
            events=["scan.completed"], enabled=True,
        )
        db.add(wh)
        await db.flush()

        async def _boom(*a, **kw):
            raise RuntimeError("connect to 10.9.9.9:5432 refused (internal detail)")

        with _fake_dns(["93.184.216.34"]), \
             patch("app.api.v1.endpoints.webhooks.post_webhook", new=_boom):
            resp = await client.post(
                f"/api/v1/orgs/{org_id}/webhooks/{wh.id}/test", headers=auth_headers(token)
            )
        assert resp.status_code == 502
        assert "10.9.9.9" not in resp.text
        assert "internal detail" not in resp.text


# ── 5. forgot / reset password ───────────────────────────────────────────────

class TestForgotPassword:
    async def test_existing_and_unknown_email_identical_204(self, client):
        email = _email("fp")
        await register_user(client, email=email)
        sent = AsyncMock()
        with patch("app.services.email_service.send_password_reset_email", new=sent):
            r1 = await client.post("/api/v1/auth/forgot-password", json={"email": email})
            r2 = await client.post("/api/v1/auth/forgot-password", json={"email": _email("nobody")})
        assert r1.status_code == 204
        assert r2.status_code == 204
        assert r1.content == r2.content == b""
        sent.assert_awaited_once()

    async def test_backend_failure_still_204(self, client):
        email = _email("fp-fail")
        await register_user(client, email=email)
        with patch("app.core.redis_client.get_redis", side_effect=ConnectionError("redis down")):
            resp = await client.post("/api/v1/auth/forgot-password", json={"email": email})
        assert resp.status_code == 204

    async def test_reset_token_single_use_and_unlocks(self, client, db):
        email = _email("fp-reset")
        await register_user(client, email=email)
        await db.execute(
            update(User).where(User.email == email).values(
                failed_login_attempts=4,
                locked_until=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
        )
        await db.flush()

        sent = AsyncMock()
        with patch("app.services.email_service.send_password_reset_email", new=sent):
            r = await client.post("/api/v1/auth/forgot-password", json={"email": email})
        assert r.status_code == 204
        token = sent.await_args.kwargs["token"]

        new_pw = "BrandNewPass1!Secure"
        r1 = await client.post(
            "/api/v1/auth/reset-password", json={"token": token, "new_password": new_pw}
        )
        assert r1.status_code == 204, r1.text
        r2 = await client.post(
            "/api/v1/auth/reset-password", json={"token": token, "new_password": new_pw}
        )
        assert r2.status_code == 400

        user = (await db.execute(select(User).where(User.email == email))).scalar_one()
        await db.refresh(user)
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
