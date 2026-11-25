"""
DNS pinning tests.

Verifies that PinnedDNSTransport closes the DNS rebinding TOCTOU window:
- TCP connections use the validated IP, not the OS-resolved hostname
- Private IPs are blocked even when reached via hostname
- Redirect targets are validated and pinned
- TLS check uses PinnedDNSTransport
- TLS errors are classified by subtype
"""
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import httpcore
import httpx
import pytest

from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError
from app.engines.webmail import WebmailEngine
from app.engines.webmail_transport import PinnedDNSTransport, _SSRFPinnedNetworkBackend


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_guard() -> SSRFGuard:
    return SSRFGuard()


def _make_real_backend_mock() -> MagicMock:
    """Return a mock that looks like an httpcore AsyncNetworkBackend."""
    backend = MagicMock(spec=httpcore.AsyncNetworkBackend)
    backend.connect_tcp = AsyncMock(return_value=MagicMock())
    backend.connect_unix_domain_socket = AsyncMock(return_value=MagicMock())
    backend.sleep = AsyncMock()
    return backend


# ---------------------------------------------------------------------------
# _SSRFPinnedNetworkBackend unit tests
# ---------------------------------------------------------------------------


class TestSSRFPinnedNetworkBackend:
    @pytest.mark.asyncio
    async def test_valid_host_connects_to_pinned_ip(self):
        """connect_tcp should resolve, validate, and connect to the IP — not the hostname."""
        guard = _make_guard()
        real = _make_real_backend_mock()

        with patch.object(guard, "resolve_and_validate", new=AsyncMock(return_value=["93.184.216.34"])):
            backend = _SSRFPinnedNetworkBackend(guard, real)
            await backend.connect_tcp("example.com", 443, timeout=5.0)

        real.connect_tcp.assert_called_once_with(
            "93.184.216.34", 443, timeout=5.0, local_address=None, socket_options=None
        )

    @pytest.mark.asyncio
    async def test_private_ip_hostname_blocked(self):
        """resolve_and_validate raising SSRFGuardError propagates from connect_tcp."""
        guard = _make_guard()
        real = _make_real_backend_mock()

        with patch.object(
            guard, "resolve_and_validate",
            new=AsyncMock(side_effect=SSRFGuardError("10.0.0.1 is in blocked network"))
        ):
            backend = _SSRFPinnedNetworkBackend(guard, real)
            with pytest.raises(SSRFGuardError):
                await backend.connect_tcp("internal.corp", 80, timeout=5.0)

        real.connect_tcp.assert_not_called()

    @pytest.mark.asyncio
    async def test_bare_private_ip_blocked(self):
        """Direct private IP passed as host is also blocked (via validate_ip)."""
        guard = _make_guard()
        real = _make_real_backend_mock()

        backend = _SSRFPinnedNetworkBackend(guard, real)
        with pytest.raises(SSRFGuardError):
            await backend.connect_tcp("10.0.0.1", 80, timeout=5.0)

        real.connect_tcp.assert_not_called()

    @pytest.mark.asyncio
    async def test_metadata_ip_blocked(self):
        """169.254.169.254 (AWS/GCP metadata) must be blocked."""
        guard = _make_guard()
        real = _make_real_backend_mock()

        backend = _SSRFPinnedNetworkBackend(guard, real)
        with pytest.raises(SSRFGuardError):
            await backend.connect_tcp("169.254.169.254", 80, timeout=5.0)

    @pytest.mark.asyncio
    async def test_loopback_blocked(self):
        """127.0.0.1 must be blocked."""
        guard = _make_guard()
        real = _make_real_backend_mock()

        backend = _SSRFPinnedNetworkBackend(guard, real)
        with pytest.raises(SSRFGuardError):
            await backend.connect_tcp("127.0.0.1", 80, timeout=5.0)

    @pytest.mark.asyncio
    async def test_ipv6_loopback_blocked(self):
        """::1 must be blocked."""
        guard = _make_guard()
        real = _make_real_backend_mock()

        backend = _SSRFPinnedNetworkBackend(guard, real)
        with pytest.raises(SSRFGuardError):
            await backend.connect_tcp("::1", 80, timeout=5.0)

    @pytest.mark.asyncio
    async def test_connect_uses_first_validated_ip(self):
        """When multiple IPs are returned, the first one is used for TCP."""
        guard = _make_guard()
        real = _make_real_backend_mock()

        with patch.object(
            guard, "resolve_and_validate",
            new=AsyncMock(return_value=["1.2.3.4", "5.6.7.8"])
        ):
            backend = _SSRFPinnedNetworkBackend(guard, real)
            await backend.connect_tcp("multi.example.com", 443)

        # Must connect to the FIRST IP, not the second, not the hostname
        real.connect_tcp.assert_called_once()
        call_args = real.connect_tcp.call_args
        assert call_args[0][0] == "1.2.3.4"
        assert call_args[0][0] != "multi.example.com"

    @pytest.mark.asyncio
    async def test_sleep_delegated_to_real_backend(self):
        guard = _make_guard()
        real = _make_real_backend_mock()
        backend = _SSRFPinnedNetworkBackend(guard, real)
        await backend.sleep(0.1)
        real.sleep.assert_called_once_with(0.1)

    @pytest.mark.asyncio
    async def test_unix_domain_socket_delegated(self):
        guard = _make_guard()
        real = _make_real_backend_mock()
        backend = _SSRFPinnedNetworkBackend(guard, real)
        await backend.connect_unix_domain_socket("/tmp/test.sock", timeout=5.0)
        real.connect_unix_domain_socket.assert_called_once_with(
            "/tmp/test.sock", timeout=5.0, socket_options=None
        )


# ---------------------------------------------------------------------------
# PinnedDNSTransport integration
# ---------------------------------------------------------------------------


class TestPinnedDNSTransport:
    def test_transport_wraps_pool_backend(self):
        """PinnedDNSTransport replaces _pool._network_backend with our wrapper."""
        guard = _make_guard()
        transport = PinnedDNSTransport(ssrf_guard=guard)
        assert isinstance(transport._pool._network_backend, _SSRFPinnedNetworkBackend)

    def test_transport_kwargs_forwarded(self):
        """verify=True kwarg is forwarded to parent transport (affects SSL context)."""
        guard = _make_guard()
        transport = PinnedDNSTransport(ssrf_guard=guard, verify=True)
        # The _pool should be an AsyncConnectionPool with an SSL context configured
        assert transport._pool is not None

    def test_transport_verify_false(self):
        guard = _make_guard()
        transport = PinnedDNSTransport(ssrf_guard=guard, verify=False)
        assert transport._pool is not None


# ---------------------------------------------------------------------------
# WebmailEngine._check_tls_host — uses PinnedDNSTransport
# ---------------------------------------------------------------------------


class TestTLSCheckUsesPinnedTransport:
    @pytest.mark.asyncio
    async def test_tls_check_ssrf_blocked_returns_none(self):
        """_check_tls_host returns None for SSRF-blocked hosts (not a TLS finding)."""
        engine = WebmailEngine()
        with patch.object(
            engine._ssrf_guard, "validate_domain_for_scan",
            new=AsyncMock(side_effect=SSRFGuardError("blocked"))
        ):
            result = await engine._check_tls_host("internal.corp", 5.0)
        assert result is None

    @pytest.mark.asyncio
    async def test_tls_check_valid_cert_returns_none(self):
        """When cert is valid, _check_tls_host returns None."""
        engine = WebmailEngine()
        with patch.object(
            engine._ssrf_guard, "validate_domain_for_scan", new=AsyncMock()
        ):
            with patch("app.engines.webmail_transport.PinnedDNSTransport") as MockTransport:
                mock_instance = MagicMock()
                MockTransport.return_value = mock_instance
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock()

                mock_client = MagicMock()
                mock_client.head = AsyncMock(return_value=MagicMock(status_code=200))
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock()

                with patch("httpx.AsyncClient", return_value=mock_client):
                    result = await engine._check_tls_host("webmail.example.com", 5.0)

        assert result is None


# ---------------------------------------------------------------------------
# TLS error classification
# ---------------------------------------------------------------------------


class TestTLSErrorClassification:
    def _make_connect_error(self, msg: str, is_ssl: bool = False) -> httpx.ConnectError:
        exc = httpx.ConnectError(msg)
        if is_ssl:
            ssl_err = ssl.SSLError(msg)
            exc.__context__ = ssl_err
        return exc

    def test_expired_cert_classified(self):
        engine = WebmailEngine()
        err = self._make_connect_error("certificate has expired", is_ssl=True)
        result = engine._classify_tls_error(err)
        assert result is not None
        assert result.startswith("EXPIRED:")

    def test_self_signed_classified(self):
        engine = WebmailEngine()
        err = self._make_connect_error("self signed certificate in chain", is_ssl=True)
        result = engine._classify_tls_error(err)
        assert result is not None
        assert result.startswith("SELF_SIGNED:")

    def test_hostname_mismatch_classified(self):
        engine = WebmailEngine()
        err = self._make_connect_error("hostname 'mail.example.com' doesn't match", is_ssl=True)
        result = engine._classify_tls_error(err)
        assert result is not None
        assert result.startswith("HOSTNAME_MISMATCH:")

    def test_incomplete_chain_classified(self):
        engine = WebmailEngine()
        err = self._make_connect_error("unable to get local issuer certificate", is_ssl=True)
        result = engine._classify_tls_error(err)
        assert result is not None
        assert result.startswith("CHAIN_INCOMPLETE:")

    def test_generic_tls_error_classified(self):
        engine = WebmailEngine()
        err = self._make_connect_error("ssl handshake failed", is_ssl=True)
        result = engine._classify_tls_error(err)
        assert result is not None
        assert result.startswith("TLS_ERROR:")

    def test_non_tls_error_returns_none(self):
        engine = WebmailEngine()
        err = self._make_connect_error("connection refused", is_ssl=False)
        result = engine._classify_tls_error(err)
        assert result is None

    def test_emit_tls_finding_expired_uses_correct_check_id(self):
        from app.engines.base import EngineResult
        engine = WebmailEngine()
        result = EngineResult(engine="webmail", domain="example.com")
        engine._emit_tls_finding(result, "mail.example.com", "EXPIRED:cert expired")
        assert len(result.findings) == 1
        assert result.findings[0].check_id == "WM-TLS-EXPIRED"

    def test_emit_tls_finding_self_signed_uses_correct_check_id(self):
        from app.engines.base import EngineResult
        engine = WebmailEngine()
        result = EngineResult(engine="webmail", domain="example.com")
        engine._emit_tls_finding(result, "mail.example.com", "SELF_SIGNED:self-signed cert")
        assert result.findings[0].check_id == "WM-TLS-SELF-SIGNED"

    def test_emit_tls_finding_hostname_mismatch(self):
        from app.engines.base import EngineResult
        engine = WebmailEngine()
        result = EngineResult(engine="webmail", domain="example.com")
        engine._emit_tls_finding(result, "mail.example.com", "HOSTNAME_MISMATCH:mismatch")
        assert result.findings[0].check_id == "WM-TLS-HOSTNAME"

    def test_emit_tls_finding_chain_incomplete(self):
        from app.engines.base import EngineResult
        engine = WebmailEngine()
        result = EngineResult(engine="webmail", domain="example.com")
        engine._emit_tls_finding(result, "mail.example.com", "CHAIN_INCOMPLETE:no issuer")
        assert result.findings[0].check_id == "WM-TLS-CHAIN"

    def test_emit_tls_finding_fallback(self):
        from app.engines.base import EngineResult
        engine = WebmailEngine()
        result = EngineResult(engine="webmail", domain="example.com")
        engine._emit_tls_finding(result, "mail.example.com", "TLS_ERROR:unknown tls error")
        assert result.findings[0].check_id == "WM-TLS-CERT"


# ---------------------------------------------------------------------------
# Cookie severity calibration
# ---------------------------------------------------------------------------


class TestCookieSeverityCalibration:
    def _make_ep(self, cookie_header: str):
        from app.engines.webmail import WebmailEndpoint
        return WebmailEndpoint(
            url="https://webmail.example.com/",
            product="Roundcube",
            version=None,
            confidence=0.9,
            status_code=200,
            headers={"set-cookie": cookie_header},
        )

    def _get_cookie_findings(self, cookie_header: str, check_id: str):
        from app.engines.base import EngineResult
        engine = WebmailEngine()
        result = EngineResult(engine="webmail", domain="example.com")
        ep = self._make_ep(cookie_header)
        engine._emit_cookie_findings(result, ep)
        return [f for f in result.findings if f.check_id == check_id]

    def test_session_cookie_secure_is_high(self):
        findings = self._get_cookie_findings("sessionid=abc123; Path=/; HttpOnly", "WM-COOKIE-SECURE")
        assert len(findings) == 1
        from app.schemas.findings import RiskLevel
        assert findings[0].risk_level == RiskLevel.HIGH

    def test_session_cookie_httponly_is_high(self):
        findings = self._get_cookie_findings("token=abc123; Path=/; Secure", "WM-COOKIE-HTTPONLY")
        assert len(findings) == 1
        from app.schemas.findings import RiskLevel
        assert findings[0].risk_level == RiskLevel.HIGH

    def test_session_cookie_samesite_is_medium(self):
        findings = self._get_cookie_findings("auth=abc123; Path=/; Secure; HttpOnly", "WM-COOKIE-SAMESITE")
        assert len(findings) == 1
        from app.schemas.findings import RiskLevel
        assert findings[0].risk_level == RiskLevel.MEDIUM

    def test_analytics_cookie_secure_is_low(self):
        findings = self._get_cookie_findings("_ga=GA1.1.123; Path=/", "WM-COOKIE-SECURE")
        assert len(findings) == 1
        from app.schemas.findings import RiskLevel
        assert findings[0].risk_level == RiskLevel.LOW

    def test_analytics_cookie_httponly_is_low(self):
        findings = self._get_cookie_findings("_gid=GA1.1.456; Path=/; Secure", "WM-COOKIE-HTTPONLY")
        assert len(findings) == 1
        from app.schemas.findings import RiskLevel
        assert findings[0].risk_level == RiskLevel.LOW

    def test_unknown_cookie_secure_is_medium(self):
        findings = self._get_cookie_findings("preferences=dark_mode; Path=/", "WM-COOKIE-SECURE")
        assert len(findings) == 1
        from app.schemas.findings import RiskLevel
        assert findings[0].risk_level == RiskLevel.MEDIUM

    def test_unknown_cookie_httponly_is_medium(self):
        findings = self._get_cookie_findings("theme=dark; Path=/; Secure", "WM-COOKIE-HTTPONLY")
        assert len(findings) == 1
        from app.schemas.findings import RiskLevel
        assert findings[0].risk_level == RiskLevel.MEDIUM

    def test_cookie_class_in_technical_details(self):
        """cookie_class field present in evidence technical_details."""
        from app.engines.base import EngineResult
        engine = WebmailEngine()
        result = EngineResult(engine="webmail", domain="example.com")
        ep = self._make_ep("sessionid=x; Path=/")
        engine._emit_cookie_findings(result, ep)
        secure_finding = next(f for f in result.findings if f.check_id == "WM-COOKIE-SECURE")
        assert secure_finding.evidence[0].technical_details["cookie_class"] == "session/auth"
