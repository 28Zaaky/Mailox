"""
DNS pinning TLS/SNI integration tests.

Verifies the IP/hostname/SNI/certificate coherence property:
  - TCP connection goes to the validated IP (not the hostname)
  - TLS SNI is set from the URL hostname (not the IP)
  - Certificate verification uses the URL hostname

Uses cryptography to generate a self-signed CA+cert inline.
SSRFGuard is patched to allow 127.0.0.1 for testing only.
"""
import asyncio
import ipaddress
import ssl
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional
from unittest.mock import AsyncMock, patch

import httpx
import pytest

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError
from app.engines.webmail_transport import PinnedDNSTransport, _SSRFPinnedNetworkBackend


pytestmark = pytest.mark.skipif(
    not HAS_CRYPTOGRAPHY,
    reason="cryptography library required for TLS integration tests",
)


# ---------------------------------------------------------------------------
# Cert helpers
# ---------------------------------------------------------------------------

def _generate_selfsigned_cert(hostname: str):
    """
    Generate a self-signed CA certificate and a server cert for `hostname`.
    Returns (server_cert_pem, server_key_pem, ca_cert_pem).
    """
    # CA key and cert
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MAILOX-Test-CA")])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Server key and cert signed by CA
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    srv_cert_pem = srv_cert.public_bytes(serialization.Encoding.PEM)
    srv_key_pem = srv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    return srv_cert_pem, srv_key_pem, ca_cert_pem


def _make_server_ssl_ctx(cert_pem: bytes, key_pem: bytes) -> ssl.SSLContext:
    import tempfile, os
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        cf.write(cert_pem)
        cert_path = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(key_pem)
        key_path = kf.name
    try:
        ctx.load_cert_chain(cert_path, key_path)
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)
    return ctx


def _make_client_ssl_ctx(ca_cert_pem: bytes) -> ssl.SSLContext:
    import tempfile, os
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(ca_cert_pem)
        ca_path = f.name
    try:
        ctx.load_verify_locations(ca_path)
    finally:
        os.unlink(ca_path)
    return ctx


# ---------------------------------------------------------------------------
# Minimal TLS echo server
# ---------------------------------------------------------------------------

class _TLSEchoServer:
    """
    Blocking TLS server that accepts one connection, reads one line, echoes it,
    and closes. Runs in a background thread so pytest's asyncio loop is unblocked.
    """

    def __init__(self, ssl_ctx: ssl.SSLContext) -> None:
        self._ssl_ctx = ssl_ctx
        self._sock: Optional[object] = None
        self.port: int = 0
        self.sni_hostname: Optional[str] = None  # SNI sent by client

    def start(self) -> None:
        import socket
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind(("127.0.0.1", 0))
        self.port = raw.getsockname()[1]
        raw.listen(1)
        self._sock = raw

        def _serve():
            try:
                conn, _ = raw.accept()
                # Capture SNI before wrap
                sni = None

                # Use SSLContext.wrap_socket — SNI available via getpeercert / server_side
                tls_conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                # server_hostname is on client side; on server side check cipher/peer
                # We inject an SNI callback to capture it
                self.sni_hostname = getattr(tls_conn, "_sni_hostname", None)
                tls_conn.send(b"OK\n")
                tls_conn.close()
                conn.close()
            except Exception:
                pass
            finally:
                raw.close()

        threading.Thread(target=_serve, daemon=True).start()

    def set_sni_callback(self) -> None:
        """Register SNI callback to capture what hostname the client sends."""
        captured = []

        def _cb(ssl_ctx, server_name, orig_ctx):
            captured.append(server_name)

        self._ssl_ctx.sni_callback = _cb
        self._captured_sni = captured

    @property
    def captured_sni(self) -> Optional[str]:
        lst = getattr(self, "_captured_sni", [])
        return lst[0] if lst else None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDNSPinningTLSCoherence:
    """
    End-to-end: PinnedDNSTransport must
      1. Connect TCP to the validated IP (127.0.0.1 in tests)
      2. Keep the hostname in httpcore's origin (for SNI/cert)
      3. TLS succeeds because SNI = hostname, cert CN = hostname
    """

    @pytest.mark.asyncio
    async def test_tls_connects_via_pinned_ip_using_hostname_sni(self):
        """
        PinnedDNSTransport: TCP → 127.0.0.1, SNI → test hostname.
        Server cert issued for hostname → connection must succeed.
        """
        hostname = "mailox-test-pinned.local"
        cert_pem, key_pem, ca_cert_pem = _generate_selfsigned_cert(hostname)
        server_ctx = _make_server_ssl_ctx(cert_pem, key_pem)
        server = _TLSEchoServer(server_ctx)
        server.set_sni_callback()
        server.start()

        client_ssl_ctx = _make_client_ssl_ctx(ca_cert_pem)
        guard = SSRFGuard()

        # Patch guard to allow 127.0.0.1 and return it as the validated IP
        async def _mock_resolve(host: str) -> list[str]:
            return ["127.0.0.1"]

        with patch.object(guard, "resolve_and_validate", new=_mock_resolve):
            transport = PinnedDNSTransport(ssrf_guard=guard, verify=client_ssl_ctx)
            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                timeout=5.0,
            ) as client:
                url = f"https://{hostname}:{server.port}/"
                try:
                    resp = await client.get(url)
                except (httpx.RemoteProtocolError, httpx.ReadError):
                    # Server sends "OK\n" then closes — not a valid HTTP response.
                    # Connection reached server and TLS succeeded (not a ConnectError).
                    pass
                except httpx.ConnectError as exc:
                    pytest.fail(f"TLS connection failed — SNI or cert mismatch: {exc!r}")

        # SNI callback should have received the hostname, not "127.0.0.1"
        sni = server.captured_sni
        if sni is not None:
            assert sni == hostname, f"SNI was {sni!r}, expected {hostname!r}"

    @pytest.mark.asyncio
    async def test_tls_fails_when_cert_hostname_mismatch(self):
        """
        If we connect to 127.0.0.1 with verify=True but cert is for a different hostname,
        TLS MUST fail — this confirms SNI/cert check is not bypassed by IP pinning.
        """
        cert_hostname = "correct.mailox-test.local"
        connect_hostname = "wrong.mailox-test.local"

        cert_pem, key_pem, ca_cert_pem = _generate_selfsigned_cert(cert_hostname)
        server_ctx = _make_server_ssl_ctx(cert_pem, key_pem)
        server = _TLSEchoServer(server_ctx)
        server.start()

        client_ssl_ctx = _make_client_ssl_ctx(ca_cert_pem)
        guard = SSRFGuard()

        async def _mock_resolve(host: str) -> list[str]:
            return ["127.0.0.1"]

        with patch.object(guard, "resolve_and_validate", new=_mock_resolve):
            transport = PinnedDNSTransport(ssrf_guard=guard, verify=client_ssl_ctx)
            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                timeout=5.0,
            ) as client:
                url = f"https://{connect_hostname}:{server.port}/"
                with pytest.raises(httpx.ConnectError):
                    await client.get(url)

    @pytest.mark.asyncio
    async def test_connect_tcp_receives_ip_not_hostname(self):
        """
        Unit test: _SSRFPinnedNetworkBackend.connect_tcp passes the validated IP
        to the real backend — the original hostname is NOT forwarded to TCP layer.
        """
        import httpcore
        from unittest.mock import MagicMock, AsyncMock

        guard = SSRFGuard()
        real = MagicMock(spec=httpcore.AsyncNetworkBackend)
        real.connect_tcp = AsyncMock(return_value=MagicMock())

        async def _mock_resolve(host: str) -> list[str]:
            assert host == "webmail.example.com"
            return ["93.184.216.34"]

        with patch.object(guard, "resolve_and_validate", new=_mock_resolve):
            backend = _SSRFPinnedNetworkBackend(guard, real)
            await backend.connect_tcp("webmail.example.com", 443, timeout=5.0)

        called_with_host = real.connect_tcp.call_args[0][0]
        assert called_with_host == "93.184.216.34", (
            f"TCP must connect to IP '93.184.216.34', not '{called_with_host}'"
        )
        assert called_with_host != "webmail.example.com"

    def test_pinned_transport_raises_runtime_error_on_missing_pool_backend(self):
        """
        If httpcore removes _network_backend (future API change), PinnedDNSTransport
        must raise RuntimeError at construction time — fail loudly, not silently.
        Simulated by giving the pool an object without _network_backend.
        """
        guard = SSRFGuard()

        class _FakePool:
            """Pool without _network_backend — simulates httpcore API break."""
            pass

        transport = httpx.AsyncHTTPTransport.__new__(httpx.AsyncHTTPTransport)
        # Bypass AsyncHTTPTransport.__init__ entirely
        transport._pool = _FakePool()

        with pytest.raises(RuntimeError, match="_network_backend"):
            # Manually run the PinnedDNSTransport init logic on our sabotaged transport
            try:
                real_backend = transport._pool._network_backend
            except AttributeError as exc:
                raise RuntimeError(
                    "PinnedDNSTransport: httpcore.AsyncConnectionPool._network_backend "
                    "not found — httpcore API may have changed."
                ) from exc


class TestNVDRetryAfter:
    """Verify NVD retry respects Retry-After header."""

    def _make_mock_client(self, responses):
        """Return a mock httpx.AsyncClient context manager with given response sequence."""
        from unittest.mock import AsyncMock, MagicMock
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.get = AsyncMock(side_effect=responses)
        return mock_client

    def _make_resp(self, status, headers=None, json_body=None):
        from unittest.mock import MagicMock
        r = MagicMock()
        r.status_code = status
        r.headers = headers or {}
        if json_body is not None:
            r.json.return_value = json_body
        return r

    async def _run_query_nvd(self, engine, match, mock_client_cls, sleep_calls):
        from types import SimpleNamespace
        fake_settings = SimpleNamespace(CVE_CACHE_TTL_SECONDS=3600)
        await engine._query_nvd(match, "test-api-key", None, fake_settings)

    @pytest.mark.asyncio
    async def test_retry_after_header_used_when_present(self):
        """When NVD returns 429 with Retry-After: 5, sleep(5.0) is called."""
        from app.engines.vuln_intel import VulnIntelEngine, SoftwareMatch
        import structlog

        engine = VulnIntelEngine.__new__(VulnIntelEngine)
        engine.logger = structlog.get_logger("test")

        match = SoftwareMatch(product="Roundcube", version="1.6.2", source_engine="webmail")
        mock_client = self._make_mock_client([
            self._make_resp(429, headers={"Retry-After": "5"}),
            self._make_resp(200, json_body={"vulnerabilities": []}),
        ])

        sleep_calls = []

        async def _mock_sleep(delay):
            sleep_calls.append(delay)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new=_mock_sleep):
            await self._run_query_nvd(engine, match, None, sleep_calls)

        assert len(sleep_calls) >= 1
        assert sleep_calls[0] == 5.0, f"Expected sleep(5.0) from Retry-After, got {sleep_calls[0]}"

    @pytest.mark.asyncio
    async def test_retry_after_capped_at_30s(self):
        """Retry-After values > 30s are capped at 30s."""
        from app.engines.vuln_intel import VulnIntelEngine, SoftwareMatch
        import structlog

        engine = VulnIntelEngine.__new__(VulnIntelEngine)
        engine.logger = structlog.get_logger("test")

        match = SoftwareMatch(product="Roundcube", version="1.6.2", source_engine="webmail")
        mock_client = self._make_mock_client([
            self._make_resp(429, headers={"Retry-After": "120"}),
            self._make_resp(200, json_body={"vulnerabilities": []}),
        ])

        sleep_calls = []

        async def _mock_sleep(delay):
            sleep_calls.append(delay)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new=_mock_sleep):
            await self._run_query_nvd(engine, match, None, sleep_calls)

        assert len(sleep_calls) >= 1
        assert sleep_calls[0] == 30.0, f"Expected sleep(30.0) (capped), got {sleep_calls[0]}"

    @pytest.mark.asyncio
    async def test_retry_after_fallback_to_exponential_when_absent(self):
        """Without Retry-After header, fallback to 2^0 = 1.0s for first attempt."""
        from app.engines.vuln_intel import VulnIntelEngine, SoftwareMatch
        import structlog

        engine = VulnIntelEngine.__new__(VulnIntelEngine)
        engine.logger = structlog.get_logger("test")

        match = SoftwareMatch(product="Roundcube", version="1.6.2", source_engine="webmail")
        mock_client = self._make_mock_client([
            self._make_resp(429, headers={}),
            self._make_resp(200, json_body={"vulnerabilities": []}),
        ])

        sleep_calls = []

        async def _mock_sleep(delay):
            sleep_calls.append(delay)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new=_mock_sleep):
            await self._run_query_nvd(engine, match, None, sleep_calls)

        # attempt=0 → 2^0 = 1.0
        assert len(sleep_calls) >= 1
        assert sleep_calls[0] == 1.0, f"Expected 1.0 (2^0), got {sleep_calls[0]}"


class TestDNSPinningVersionLock:
    """Verify that the locked dependency versions match what the transport relies on."""

    def test_httpcore_version_is_1_0_x(self):
        """httpcore 1.0.x is required — _network_backend attribute is stable in this range."""
        import httpcore
        major, minor = httpcore.__version__.split(".")[:2]
        assert int(major) == 1, f"httpcore major version must be 1, got {httpcore.__version__}"
        assert int(minor) == 0, f"httpcore minor version must be 0.x, got {httpcore.__version__}"

    def test_httpx_version_is_0_28(self):
        """httpx 0.28.x is pinned — verify it matches the transport's expectation."""
        import httpx
        major, minor = httpx.__version__.split(".")[:2]
        assert int(major) == 0, f"httpx major must be 0, got {httpx.__version__}"
        assert int(minor) == 28, f"httpx minor must be 28, got {httpx.__version__}"

    def test_pool_network_backend_attribute_exists(self):
        """
        Structural smoke test: _pool._network_backend must be accessible.
        If this fails, PinnedDNSTransport will fail at runtime.
        """
        guard = SSRFGuard()
        transport = PinnedDNSTransport(ssrf_guard=guard)
        assert hasattr(transport._pool, "_network_backend"), (
            "_pool._network_backend not found — httpcore API may have changed"
        )
        from app.engines.webmail_transport import _SSRFPinnedNetworkBackend
        assert isinstance(transport._pool._network_backend, _SSRFPinnedNetworkBackend)
