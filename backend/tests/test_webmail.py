"""
WebmailEngine tests.
All HTTP calls mocked — no real network traffic.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.engines.webmail import WebmailEngine
from app.schemas.findings import RiskLevel


# ── Helpers ────────────────────────────────────────────────────────────────────


def _mock_httpx_response(status_code: int, headers: dict, body: str = ""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.url = MagicMock()
    resp.url.__str__ = lambda self: "https://webmail.example.com/roundcube/"
    resp.headers = {k.lower(): v for k, v in headers.items()}
    resp.text = body
    resp.history = []
    return resp


def _make_engine():
    return WebmailEngine(timeout=30.0)


# ── Fingerprinting ─────────────────────────────────────────────────────────────


class TestFingerprint:
    def test_roundcube_body_signal(self):
        engine = _make_engine()
        product, confidence, signals = engine._fingerprint(
            "Roundcube",
            "https://webmail.example.com/roundcube/",
            {},
            '<html><title>Roundcube Webmail</title><div class="rcmlogon"></div></html>',
            200,
        )
        assert product == "Roundcube"
        assert confidence >= 0.8

    def test_zimbra_header_signal(self):
        engine = _make_engine()
        product, confidence, signals = engine._fingerprint(
            "Zimbra",
            "https://mail.example.com/zimbra/",
            {"x-zimbra-error": "some-error"},
            "",
            200,
        )
        assert product == "Zimbra"
        assert confidence >= 0.9

    def test_owa_body_signal(self):
        engine = _make_engine()
        product, confidence, signals = engine._fingerprint(
            "Microsoft OWA",
            "https://mail.example.com/owa/",
            {},
            '<div>Outlook Web App</div>',
            200,
        )
        assert product == "Microsoft OWA"
        assert confidence >= 0.8

    def test_owa_version_header(self):
        engine = _make_engine()
        product, confidence, signals = engine._fingerprint(
            "Microsoft OWA",
            "https://mail.example.com/owa/",
            {"x-owa-version": "15.1.2375.17"},
            "",
            200,
        )
        assert product == "Microsoft OWA"
        assert confidence >= 0.9

    def test_unknown_no_signals(self):
        engine = _make_engine()
        product, confidence, signals = engine._fingerprint(
            "Unknown",
            "https://example.com/",
            {},
            "<html><body>Hello</body></html>",
            200,
        )
        # With no signals, confidence stays low regardless of product
        assert confidence <= 0.4

    def test_404_not_interesting(self):
        engine = _make_engine()
        # 404 returns None from _probe_url — not tested here directly
        # but fingerprint should not inflate confidence for non-webmail body
        product, confidence, _ = engine._fingerprint(
            "Unknown",
            "https://example.com/nonexistent",
            {},
            "<html>Not Found</html>",
            404,
        )
        assert confidence <= 0.3


class TestVersionExtraction:
    def test_owa_version_from_header(self):
        engine = _make_engine()
        v = engine._extract_version("Microsoft OWA", {"x-owa-version": "15.1.2375.17"}, "")
        assert v == "15.1.2375.17"

    def test_sogo_version_from_header(self):
        engine = _make_engine()
        v = engine._extract_version("SOGo", {"x-sogo-version": "5.3.0"}, "")
        assert v == "5.3.0"

    def test_roundcube_version_from_body(self):
        engine = _make_engine()
        v = engine._extract_version(
            "Roundcube",
            {},
            "Roundcube Webmail 1.6.3 login page",
        )
        assert v == "1.6.3"

    def test_no_version_returns_none(self):
        engine = _make_engine()
        v = engine._extract_version("Horde", {}, "<html>Horde webmail login</html>")
        assert v is None


# ── SSRF Guard ─────────────────────────────────────────────────────────────────


class TestSSRFGuardIntegration:
    @pytest.mark.asyncio
    async def test_ssrf_blocked_private_ip(self):
        """Engine must not probe 192.168.x.x even if it's a resolved IP."""
        engine = _make_engine()
        from app.engines.ssrf_guard import SSRFGuardError

        with patch.object(engine._ssrf_guard, "validate_domain_for_scan", side_effect=SSRFGuardError("private IP")):
            # _probe_host returns empty list when SSRF guard fires
            async with __import__("httpx").AsyncClient() as client:
                result = await engine._probe_host(client, "192.168.1.1", "192.168.1.1")
            assert result == []

    @pytest.mark.asyncio
    async def test_ssrf_blocked_localhost(self):
        engine = _make_engine()
        from app.engines.ssrf_guard import SSRFGuardError

        with patch.object(engine._ssrf_guard, "validate_domain_for_scan", side_effect=SSRFGuardError("loopback")):
            async with __import__("httpx").AsyncClient() as client:
                result = await engine._probe_host(client, "localhost", "localhost")
            assert result == []


# ── Finding emission ───────────────────────────────────────────────────────────


class TestFindingEmission:
    def _make_endpoint(self, product="Roundcube", version="1.6.2", confidence=0.9):
        from app.engines.webmail import WebmailEndpoint
        return WebmailEndpoint(
            url="https://webmail.example.com/roundcube/",
            product=product,
            version=version,
            confidence=confidence,
            status_code=200,
            headers={},
            fingerprint_signals=["body:rcmlogon"],
        )

    def test_discovery_finding_emitted(self):
        engine = _make_engine()
        from app.engines.base import EngineResult
        result = EngineResult(engine="webmail", domain="example.com")
        ep = self._make_endpoint()
        engine._emit_discovery_finding(result, ep)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.check_id == "WM-001"
        assert "Roundcube" in f.title

    def test_version_exposed_raises_to_low_risk(self):
        engine = _make_engine()
        from app.engines.base import EngineResult
        result = EngineResult(engine="webmail", domain="example.com")
        ep = self._make_endpoint(version="1.6.2")
        engine._emit_discovery_finding(result, ep)
        assert result.findings[0].risk_level == RiskLevel.LOW

    def test_no_version_stays_info(self):
        engine = _make_engine()
        from app.engines.base import EngineResult
        result = EngineResult(engine="webmail", domain="example.com")
        ep = self._make_endpoint(version=None)
        engine._emit_discovery_finding(result, ep)
        assert result.findings[0].risk_level == RiskLevel.INFO

    def test_missing_hsts_finding_emitted(self):
        engine = _make_engine()
        from app.engines.base import EngineResult
        result = EngineResult(engine="webmail", domain="example.com")
        ep = self._make_endpoint()
        ep.headers = {}  # no HSTS
        engine._emit_security_header_findings(result, ep)
        check_ids = [f.check_id for f in result.findings]
        assert any("HSTS" in c or "STRICT" in c for c in check_ids)

    def test_present_hsts_no_finding(self):
        engine = _make_engine()
        from app.engines.base import EngineResult
        result = EngineResult(engine="webmail", domain="example.com")
        ep = self._make_endpoint()
        ep.headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }
        engine._emit_security_header_findings(result, ep)
        # All headers present — no findings
        assert len(result.findings) == 0

    def test_x_powered_by_disclosure(self):
        engine = _make_engine()
        from app.engines.base import EngineResult
        result = EngineResult(engine="webmail", domain="example.com")
        ep = self._make_endpoint()
        ep.headers = {"x-powered-by": "PHP/7.4.3"}
        engine._emit_info_disclosure_findings(result, ep)
        assert len(result.findings) == 1
        assert "X-Powered-By" in result.findings[0].title


# ── Full engine run (mocked HTTP) ─────────────────────────────────────────────


class TestWebmailEngineRun:
    @pytest.mark.asyncio
    async def test_run_returns_engine_result(self):
        engine = _make_engine()
        with patch.object(engine._ssrf_guard, "validate_domain_for_scan", new_callable=AsyncMock):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                # All probes return connection error
                mock_client.get = AsyncMock(side_effect=__import__("httpx").ConnectError("refused"))
                mock_client_cls.return_value = mock_client

                result = await engine._run("example.com")

        assert result.engine == "webmail"
        assert result.domain == "example.com"
        assert result.error is None
        assert isinstance(result.findings, list)

    @pytest.mark.asyncio
    async def test_run_no_findings_on_connect_error(self):
        engine = _make_engine()
        with patch.object(engine._ssrf_guard, "validate_domain_for_scan", new_callable=AsyncMock):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(side_effect=__import__("httpx").ConnectError("refused"))
                mock_client_cls.return_value = mock_client

                result = await engine._run("example.com")

        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_timeout_does_not_raise(self):
        """Engine wraps _run in BaseEngine.run() — timeout returns EngineResult.error."""
        engine = WebmailEngine(timeout=0.001)
        with patch.object(engine._ssrf_guard, "validate_domain_for_scan", new_callable=AsyncMock):
            with patch("httpx.AsyncClient") as mock_client_cls:
                import asyncio
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                async def _slow(*a, **kw):
                    await asyncio.sleep(10)
                mock_client.get = _slow
                mock_client_cls.return_value = mock_client

                result = await engine.run("example.com")

        # run() captures TimeoutError — no exception, error field set
        assert result.error is not None
        assert "timed out" in result.error.lower()
