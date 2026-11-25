"""Regression tests for the open-source (self-hosted) release fixes.

- Settings ignore unknown .env keys
- finding titles never overflow their VARCHAR column
- worker: fresh event loop per task + async engine disposal, FAILED instead of a
  scan stuck in QUEUED, engine runs only for the engines of the profile
- POST /scans returns project_id
- /auth/local-session and first-user bootstrap: strict local check
- SaaS: no platform-admin exemption from domain ownership, offensive modules
  off by default for new organizations
- SaaS-only routes answer 404 on a self-hosted instance
"""
import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import SCANNER_USER_AGENT, Settings, settings
from app.db.models.user import User
from app.db.session import get_db
from app.main import app
from tests.conftest import (
    TEST_DB_URL_ASYNC,
    TEST_PASSWORD,
    auth_headers,
    login_user,
    make_invite,
    register_user,
)


def _email(tag: str) -> str:
    return f"{tag}-{uuid.uuid4().hex[:10]}@oss-fixes.dev"


def _client_from(db, host: str) -> AsyncClient:
    async def _override_get_db():
        try:
            yield db
            await db.commit()
        except Exception:
            await db.rollback()
            raise

    app.dependency_overrides[get_db] = _override_get_db
    return AsyncClient(transport=ASGITransport(app=app, client=(host, 40000)), base_url="https://test")


# ── 1. Settings ──────────────────────────────────────────────────────────────

class TestSettingsExtraKeys:
    def test_unknown_env_file_key_is_ignored(self, tmp_path):
        # .env.selfhosted used to ship APP_ENV=production: unknown keys read from the
        # env file raised "Extra inputs are not permitted" and crashed every process.
        env_file = tmp_path / ".env"
        env_file.write_text("APP_ENV=production\nSOME_FUTURE_KEY=1\n", encoding="utf-8")
        s = Settings(_env_file=str(env_file))
        assert not hasattr(s, "APP_ENV")

    def test_known_fields_still_validated(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "short")
        with pytest.raises(Exception):
            Settings()

    def test_neutral_defaults(self):
        assert Settings.model_fields["SMTP_FROM"].default == "mailox@localhost"
        assert SCANNER_USER_AGENT == (
            f"MAILOX/{settings.APP_VERSION} (+https://github.com/28Zaaky/Mailox)"
        )
        from app.engines import web_pentest, web_security
        assert web_pentest._SCANNER_HEADER["User-Agent"] == SCANNER_USER_AGENT
        assert web_security._USER_AGENT == SCANNER_USER_AGENT


# ── 2. Finding title length ──────────────────────────────────────────────────

class TestFindingTitleLength:
    def test_scan_finding_title_and_asset_truncated(self):
        from app.db.models.scan import ScanFinding
        f = ScanFinding(title="T" * 422, affected_asset="a" * 300)
        assert len(f.title) == 255 and f.title.endswith("…")
        assert len(f.affected_asset) == 255
        assert ScanFinding(title="short").title == "short"

    def test_canonical_finding_title_truncated(self):
        from app.db.models.finding import CanonicalFinding
        assert len(CanonicalFinding(title="x" * 900).title) == 500

    def test_dns_provider_title_is_short(self):
        from app.engines.dns_auth import _summary_title
        names = ["Google Workspace", "SendGrid", "Mailchimp", "Amazon SES", "Mailgun"] * 6
        title = _summary_title("Mail provider identified", names)
        assert title == "Mail provider identified: Google Workspace, SendGrid (+28 more)"
        assert _summary_title("X", ["A"]) == "X: A"

    async def test_long_title_persists(self, db):
        """The 422-char title seen on example.com is stored, not rejected by Postgres."""
        from app.db.models.organization import Organization
        from app.db.models.scan import RiskLevel, Scan, ScanFinding, ScanStatus
        org = Organization(name="T", slug=f"t-{uuid.uuid4().hex[:8]}")
        db.add(org)
        await db.flush()
        scan = Scan(org_id=org.id, target_domain="example.com", status=ScanStatus.COMPLETED,
                    created_at=datetime.now(timezone.utc))
        db.add(scan)
        await db.flush()
        db.add(ScanFinding(
            scan_id=scan.id, engine="dns_auth", check_id="DNS-PROVIDER-01",
            title="Mail provider identified: " + ", ".join(["Provider"] * 50),
            description="d", risk_level=RiskLevel.INFO, confidence=1.0,
            evidence=[], remediation="",
        ))
        await db.flush()
        stored = (await db.execute(
            select(ScanFinding.title).where(ScanFinding.scan_id == scan.id)
        )).scalar_one()
        assert len(stored) == 255


# ── 3. Worker event loop / engine disposal ───────────────────────────────────

class TestWorkerEventLoop:
    def test_run_async_disposes_engine_between_loops(self):
        """Two tasks in a row on fresh loops must not reuse a connection bound to
        the previous loop ("Future attached to a different loop")."""
        from sqlalchemy import text
        from app.db.session import AsyncSessionLocal
        from app.worker.tasks import _run_async

        async def _query():
            async with AsyncSessionLocal() as s:
                return (await s.execute(text("SELECT 1"))).scalar_one()

        for _ in range(3):
            assert _run_async(_query()) == 1

    def test_scan_marked_failed_when_retries_exhausted(self):
        """A failure escaping _run_scan with no retry left must not leave the scan
        QUEUED without an error message."""
        from sqlalchemy import create_engine, delete, text
        from sqlalchemy.orm import Session
        from app.db.models.organization import Organization
        from app.db.models.scan import Scan, ScanStatus
        from app.worker import tasks
        from tests.conftest import TEST_DB_URL_SYNC

        eng = create_engine(TEST_DB_URL_SYNC)
        org_id, scan_id = uuid.uuid4(), uuid.uuid4()
        with Session(eng) as s:
            s.add(Organization(id=org_id, name="W", slug=f"w-{uuid.uuid4().hex[:8]}"))
            s.flush()
            s.add(Scan(id=scan_id, org_id=org_id, target_domain="example.com",
                       status=ScanStatus.QUEUED, created_at=datetime.now(timezone.utc)))
            s.commit()
        try:
            async def _boom(scan_id_, task):
                raise RuntimeError("Future attached to a different loop")

            with patch.object(tasks, "_run_scan", _boom), \
                 patch.object(tasks.scan_task, "max_retries", 0):
                with pytest.raises(RuntimeError):
                    tasks.scan_task.run(str(scan_id))
            with Session(eng) as s:
                row = s.get(Scan, scan_id)
                assert row.status == ScanStatus.FAILED
                assert row.error_msg and "RuntimeError" in row.error_msg
        finally:
            with Session(eng) as s:
                s.execute(delete(Scan).where(Scan.id == scan_id))
                s.execute(delete(Organization).where(Organization.id == org_id))
                s.commit()
            eng.dispose()


# ── 4/5. Engine runs follow the profile ──────────────────────────────────────

@pytest.mark.edition("selfhosted")
class TestEngineRunsFollowProfile:
    async def _run(self, engines):
        from sqlalchemy import delete
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from sqlalchemy.pool import NullPool
        from app.db.models.organization import Organization
        from app.db.models.profile import AssessmentProfile
        from app.db.models.scan import Scan, ScanEngineRun, ScanOutbox, ScanStatus
        from app.worker.tasks import _run_scan
        from tests.worker_db_mock import stub_aux_engines

        engine = create_async_engine(TEST_DB_URL_ASYNC, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
        org_id, scan_id, profile_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        now = datetime.now(timezone.utc)
        async with SessionLocal() as s:
            s.add(Organization(id=org_id, name="P", slug=f"p-{uuid.uuid4().hex[:8]}"))
            await s.flush()
            if engines is not None:
                s.add(AssessmentProfile(id=profile_id, org_id=org_id, name="p", engines=engines,
                                        config={}, created_at=now, is_builtin=False))
                await s.flush()
            s.add(Scan(id=scan_id, org_id=org_id, target_domain="example.com",
                       status=ScanStatus.QUEUED, created_at=now,
                       profile_id=profile_id if engines is not None else None))
            await s.commit()

        empty = MagicMock(findings=[], success=True, error=None, metadata={})
        task = MagicMock(max_retries=0)
        task.request.retries = 0
        try:
            with patch("app.engines.dns_auth.DNSAuthEngine") as dns, \
                 patch("app.engines.smtp_discovery.SMTPDiscoveryEngine") as smtp, \
                 patch("app.engines.webmail.WebmailEngine") as wm, \
                 patch("app.engines.vuln_intel.VulnIntelEngine") as vi, \
                 stub_aux_engines(), \
                 patch("app.db.session.AsyncSessionLocal", SessionLocal):
                dns.return_value.run = AsyncMock(return_value=empty)
                smtp.return_value.run = AsyncMock(return_value=empty)
                wm.return_value.run = AsyncMock(return_value=empty)
                vi.return_value.run_from_findings = AsyncMock(return_value=empty)
                await _run_scan(str(scan_id), task)
            async with SessionLocal() as s:
                runs = (await s.execute(
                    select(ScanEngineRun.engine, ScanEngineRun.attempt_number)
                    .where(ScanEngineRun.scan_id == scan_id)
                )).all()
                scan = (await s.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            return runs, scan
        finally:
            async with SessionLocal() as s:
                await s.execute(delete(ScanEngineRun).where(ScanEngineRun.scan_id == scan_id))
                await s.execute(delete(ScanOutbox).where(ScanOutbox.scan_id == scan_id))
                await s.execute(delete(Scan).where(Scan.id == scan_id))
                await s.execute(delete(AssessmentProfile).where(AssessmentProfile.id == profile_id))
                await s.execute(delete(Organization).where(Organization.id == org_id))
                await s.commit()
            await engine.dispose()

    async def test_dns_only_profile_creates_dns_run_only(self):
        from app.db.models.scan import ScanStatus
        runs, scan = await self._run(["dns_auth"])
        engines = {e for e, _ in runs}
        assert "dns_auth" in engines
        assert not engines & {"secrets", "web_security", "web_pentest", "smtp_discovery", "webmail"}
        assert scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
        assert scan.current_engine is None

    async def test_default_scan_web_security_run_has_attempt_number(self):
        runs, _ = await self._run(None)
        by_engine = dict(runs)
        assert by_engine.get("web_security") == 1
        assert by_engine.get("web_pentest") == 1


# ── 6. POST /scans returns project_id ────────────────────────────────────────

class TestScanResponseProjectId:
    async def test_project_id_in_create_response(self, client, db):
        from tests.conftest import verify_domain
        await register_user(client, email=(email := _email("pid")))
        token = (await login_user(client, email=email))["access_token"]
        org = (await client.post("/api/v1/orgs", json={"name": "Org Pid test", "slug": f"pid-{uuid.uuid4().hex[:8]}"},
                                 headers=auth_headers(token))).json()
        proj = await client.post(f"/api/v1/orgs/{org['id']}/projects", json={"name": "Project P"},
                                 headers=auth_headers(token))
        assert proj.status_code == 201, proj.text
        await verify_domain(org["id"], "example.com")

        async def _noop(self, scan):
            return None

        with patch("app.services.scan_service.ScanService._dispatch_task", new=_noop), \
             patch("app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()):
            resp = await client.post(
                f"/api/v1/orgs/{org['id']}/scans",
                json={"target_domain": "example.com", "project_id": proj.json()["id"]},
                headers=auth_headers(token),
            )
        assert resp.status_code == 201, resp.text
        assert resp.json()["project_id"] == proj.json()["id"]


# ── 7. /auth/local-session ───────────────────────────────────────────────────

@pytest.mark.edition("selfhosted")
class TestLocalSessionProxyHeaders:
    @pytest.fixture(autouse=True)
    def _enabled(self, monkeypatch):
        monkeypatch.setattr(settings, "LOCAL_SESSION_ENABLED", True)
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 0)
        yield
        app.dependency_overrides.clear()

    async def _post(self, db, host, headers=None):
        async with _client_from(db, host) as c:
            return await c.post("/api/v1/auth/local-session", headers=headers or {})

    async def test_direct_loopback_accepted(self, db):
        assert (await self._post(db, "127.0.0.1")).status_code == 200

    async def test_loopback_peer_with_loopback_xff_accepted(self, db):
        """Local browser -> Vite dev proxy (xfwd) -> API."""
        resp = await self._post(db, "127.0.0.1", {"X-Forwarded-For": "127.0.0.1"})
        assert resp.status_code == 200, resp.text

    @pytest.mark.parametrize("headers", [
        {"X-Forwarded-For": "::1"},
        {"X-Forwarded-For": "::ffff:127.0.0.1"},
        {"Forwarded": 'for="[::1]:5173"'},
        {"X-Real-IP": "127.0.0.1"},
    ])
    async def test_loopback_peer_with_other_loopback_forms_accepted(self, db, headers):
        assert (await self._post(db, "127.0.0.1", headers)).status_code == 200

    async def test_loopback_peer_with_lan_xff_rejected(self, db):
        """LAN client -> `vite --host` -> API: the TCP peer is 127.0.0.1 but it is not local."""
        resp = await self._post(db, "127.0.0.1", {"X-Forwarded-For": "192.168.1.50"})
        assert resp.status_code == 403

    @pytest.mark.parametrize("headers", [
        {"X-Forwarded-For": "127.0.0.1, 192.168.1.50"},
        {"X-Forwarded-For": "192.168.1.50, 127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "192.168.1.50"},
        {"Forwarded": "for=192.168.1.50"},
        {"Forwarded": "for=_hidden"},
        {"X-Forwarded-For": "unknown"},
        {"X-Forwarded-For": ""},
    ])
    async def test_any_non_loopback_forwarded_address_rejected(self, db, headers):
        assert (await self._post(db, "127.0.0.1", headers)).status_code == 403

    async def test_non_loopback_peer_with_loopback_xff_rejected(self, db):
        """No header trust: a remote client cannot claim to be 127.0.0.1."""
        resp = await self._post(db, "192.168.1.50", {"X-Forwarded-For": "127.0.0.1"})
        assert resp.status_code == 403

    async def test_trusted_proxy_count_does_not_open_remote_peers(self, db, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_COUNT", 1)
        resp = await self._post(db, "172.18.0.3", {"X-Forwarded-For": "127.0.0.1"})
        assert resp.status_code == 403


# ── 8. First-user bootstrap ──────────────────────────────────────────────────

@pytest.mark.edition("selfhosted")
class TestFirstUserBootstrap:
    @pytest.fixture(autouse=True)
    async def _empty_instance(self, db):
        # Run against an empty users table (rolled back with the test transaction)
        from sqlalchemy import delete
        await db.execute(delete(User))
        await db.flush()
        yield
        app.dependency_overrides.clear()

    async def _register(self, db, host, email, headers=None, invite=None):
        body = {"email": email, "password": TEST_PASSWORD}
        if invite:
            body["invite"] = invite
        async with _client_from(db, host) as c:
            return await c.post("/api/v1/auth/register", json=body, headers=headers or {})

    async def test_first_user_from_loopback_becomes_admin(self, db):
        email = _email("first")
        resp = await self._register(db, "127.0.0.1", email)
        assert resp.status_code == 201, resp.text
        user = (await db.execute(select(User).where(User.email == email))).scalar_one()
        assert user.is_platform_admin is True

    async def test_first_user_from_lan_refused(self, db):
        resp = await self._register(db, "192.168.1.50", _email("lan"))
        assert resp.status_code == 403
        assert "create-admin" in resp.json()["detail"]
        assert (await db.execute(select(User))).first() is None

    async def test_first_user_through_proxy_from_lan_refused(self, db):
        resp = await self._register(db, "127.0.0.1", _email("vite"), {"X-Forwarded-For": "192.168.1.50"})
        assert resp.status_code == 403

    async def test_spoofed_loopback_header_refused(self, db):
        resp = await self._register(db, "203.0.113.9", _email("spoof"), {"X-Forwarded-For": "127.0.0.1"})
        assert resp.status_code == 403

    async def test_later_registrations_keep_invite_rules(self, db):
        assert (await self._register(db, "127.0.0.1", _email("owner"))).status_code == 201
        # Without invite: refused, from anywhere
        assert (await self._register(db, "127.0.0.1", _email("noinv"))).status_code == 403
        # With a valid invite: accepted, even from the LAN, and not admin
        email = _email("invited")
        resp = await self._register(db, "192.168.1.50", email, invite=await make_invite(email))
        assert resp.status_code == 201, resp.text
        user = (await db.execute(select(User).where(User.email == email))).scalar_one()
        assert user.is_platform_admin is False


# ── 9. SaaS: no admin exemption, offensive modules off by default ────────────

class TestSaasDomainGate:
    async def test_platform_admin_cannot_scan_unverified_domain(self, client, db):
        from sqlalchemy import update
        assert settings.IS_SAAS
        email = _email("sa")
        await register_user(client, email=email)
        token = (await login_user(client, email=email))["access_token"]
        org = (await client.post("/api/v1/orgs", json={"name": "Org S test", "slug": f"s-{uuid.uuid4().hex[:8]}"},
                                 headers=auth_headers(token))).json()
        await db.execute(update(User).where(User.email == email).values(is_platform_admin=True))
        await db.flush()
        with patch("app.engines.ssrf_guard.SSRFGuard.validate_domain_for_scan", new=AsyncMock()):
            resp = await client.post(
                f"/api/v1/orgs/{org['id']}/scans", json={"target_domain": "unverified.example"},
                headers=auth_headers(token),
            )
        # Refused up front (403 domain not verified, or 404 when the SaaS platform
        # admin is not allowed in customer orgs) instead of accepted then FAILED.
        assert resp.status_code in (403, 404)

    async def test_new_saas_org_has_offensive_modules_disabled(self, client, db):
        from app.db.models.organization import Organization
        email = _email("off")
        await register_user(client, email=email)
        token = (await login_user(client, email=email))["access_token"]
        org = (await client.post("/api/v1/orgs", json={"name": "Org O test", "slug": f"o-{uuid.uuid4().hex[:8]}"},
                                 headers=auth_headers(token))).json()
        row = (await db.execute(select(Organization).where(Organization.id == uuid.UUID(org["id"])))).scalar_one()
        assert row.offensive_modules_allowed is False

    @pytest.mark.edition("selfhosted")
    async def test_new_selfhosted_org_keeps_offensive_modules(self, client, db):
        from app.db.models.organization import Organization
        email = _email("on")
        await register_user(client, email=email)
        token = (await login_user(client, email=email))["access_token"]
        org = (await client.post("/api/v1/orgs", json={"name": "Org O test", "slug": f"o-{uuid.uuid4().hex[:8]}"},
                                 headers=auth_headers(token))).json()
        row = (await db.execute(select(Organization).where(Organization.id == uuid.UUID(org["id"])))).scalar_one()
        assert row.offensive_modules_allowed is True
        cfg = row.pentest_config or {}
        assert cfg.get("cred_probe_enabled") is True
        assert cfg.get("web_active_probe_enabled") is True

    async def test_new_saas_org_has_empty_pentest_config(self, client, db):
        from app.db.models.organization import Organization
        email = _email("saas-cfg")
        await register_user(client, email=email)
        token = (await login_user(client, email=email))["access_token"]
        org = (await client.post("/api/v1/orgs", json={"name": "Org SC test", "slug": f"sc-{uuid.uuid4().hex[:8]}"},
                                 headers=auth_headers(token))).json()
        row = (await db.execute(select(Organization).where(Organization.id == uuid.UUID(org["id"])))).scalar_one()
        cfg = row.pentest_config or {}
        assert not cfg.get("cred_probe_enabled")
        assert not cfg.get("web_active_probe_enabled")


# ── 10. SaaS-only routes ─────────────────────────────────────────────────────

@pytest.mark.edition("selfhosted")
class TestSaasOnlyRoutesHiddenInSelfhosted:
    async def _admin_with_org(self, client, db):
        from sqlalchemy import update
        email = _email("adm")
        await register_user(client, email=email)
        await db.execute(update(User).where(User.email == email).values(is_platform_admin=True))
        await db.flush()
        token = (await login_user(client, email=email))["access_token"]
        org = (await client.post("/api/v1/orgs", json={"name": "Org A test", "slug": f"a-{uuid.uuid4().hex[:8]}"},
                                 headers=auth_headers(token))).json()
        return token, org["id"]

    async def test_domains_404(self, client, db):
        token, org_id = await self._admin_with_org(client, db)
        resp = await client.get(f"/api/v1/orgs/{org_id}/domains", headers=auth_headers(token))
        assert resp.status_code == 404
        resp = await client.post(f"/api/v1/orgs/{org_id}/domains", json={"domain": "example.com"},
                                 headers=auth_headers(token))
        assert resp.status_code == 404

    async def test_admin_access_requests_404(self, client, db):
        token, _ = await self._admin_with_org(client, db)
        resp = await client.get("/api/v1/admin/access-requests", headers=auth_headers(token))
        assert resp.status_code == 404
        resp = await client.post(f"/api/v1/admin/access-requests/{uuid.uuid4()}/approve",
                                 headers=auth_headers(token))
        assert resp.status_code == 404

    async def test_meta_still_served(self, client):
        resp = await client.get("/api/v1/meta")
        assert resp.status_code == 200
        assert resp.json()["edition"] == "selfhosted"
        assert resp.json()["domain_verification_required"] is False

    async def test_admin_invites_still_available(self, client, db):
        token, _ = await self._admin_with_org(client, db)
        resp = await client.get("/api/v1/admin/invites", headers=auth_headers(token))
        assert resp.status_code == 200

    @pytest.mark.edition("saas")
    async def test_saas_domains_served(self, client, db):
        email = _email("sd")
        await register_user(client, email=email)
        token = (await login_user(client, email=email))["access_token"]
        org = (await client.post("/api/v1/orgs", json={"name": "Org D test", "slug": f"d-{uuid.uuid4().hex[:8]}"},
                                 headers=auth_headers(token))).json()
        resp = await client.get(f"/api/v1/orgs/{org['id']}/domains", headers=auth_headers(token))
        assert resp.status_code == 200


# ── 12. PyJWT ────────────────────────────────────────────────────────────────

class TestJwt:
    def test_python_jose_not_used(self):
        import inspect
        import app.api.deps as deps
        import app.core.security as sec
        import app.services.auth_service as svc
        assert sec.jwt.__name__ == "jwt"  # PyJWT
        for mod in (sec, deps, svc):
            assert "from jose" not in inspect.getsource(mod)

    async def test_expired_token_401(self, client):
        import jwt
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {"sub": str(uuid.uuid4()), "type": "access", "jti": "x", "role": "x", "org_id": None,
             "iat": now - timedelta(hours=2), "exp": now - timedelta(hours=1)},
            settings.SECRET_KEY.get_secret_value(), algorithm="HS256",
        )
        resp = await client.get("/api/v1/auth/me", headers=auth_headers(token))
        assert resp.status_code == 401

    @pytest.mark.parametrize("alg_token", ["none", "badsig", "noexp"])
    async def test_invalid_tokens_401(self, client, alg_token):
        import jwt
        now = datetime.now(timezone.utc)
        claims = {"sub": str(uuid.uuid4()), "type": "access", "jti": "x", "iat": now}
        if alg_token == "none":
            claims["exp"] = now.timestamp() + 600
            token = jwt.encode(claims, None, algorithm="none")
        elif alg_token == "badsig":
            claims["exp"] = now.timestamp() + 600
            token = jwt.encode(claims, "another-key-another-key-another-key!!", algorithm="HS256")
        else:
            token = jwt.encode(claims, settings.SECRET_KEY.get_secret_value(), algorithm="HS256")
        resp = await client.get("/api/v1/auth/me", headers=auth_headers(token))
        assert resp.status_code == 401


# ── DKIM wildcard records are reported once, not once per probed selector ────

import pytest as _pytest_dkim  # noqa: E402

from app.engines import dns_auth as _dns_auth  # noqa: E402


@_pytest_dkim.mark.asyncio
async def test_dkim_null_wildcard_reported_once(monkeypatch):
    async def fake_txt(_resolver, _name):
        return ["v=DKIM1; p="]

    monkeypatch.setattr(_dns_auth, "_query_txt", fake_txt)
    _, findings = await _dns_auth.DKIMAnalyser(None, selectors=["a", "b", "c"]).analyse("example.com")
    assert [f.check_id for f in findings] == ["DKIM-05"]
    assert findings[0].risk_level.value == "info"


@_pytest_dkim.mark.asyncio
async def test_dkim_real_selector_still_reported_alongside_wildcard(monkeypatch):
    async def fake_txt(_resolver, name):
        if name.startswith("s1."):
            return ["v=DKIM1; k=rsa; p="]  # revoked, differs from wildcard
        return ["v=DKIM1; p="]

    monkeypatch.setattr(_dns_auth, "_query_txt", fake_txt)
    _, findings = await _dns_auth.DKIMAnalyser(None, selectors=["s1", "s2"]).analyse("example.com")
    assert sorted(f.check_id for f in findings) == ["DKIM-02", "DKIM-05"]


@_pytest_dkim.mark.asyncio
async def test_dkim_no_wildcard_unchanged(monkeypatch):
    async def fake_txt(_resolver, name):
        return ["v=DKIM1; p="] if name.startswith("s1.") else []

    monkeypatch.setattr(_dns_auth, "_query_txt", fake_txt)
    _, findings = await _dns_auth.DKIMAnalyser(None, selectors=["s1", "s2"]).analyse("example.com")
    assert [f.check_id for f in findings] == ["DKIM-02"]
