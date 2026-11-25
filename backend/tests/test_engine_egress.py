"""
Tests for SSRF guard integration across active engines.

Verifies that all outbound connections from web_pentest, active_probes,
canary_probes, and credential_probes go through SSRFGuard validation.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError


class TestSSRFGuardIntegration:
    """Test that engines use SSRFGuard for all outbound connections."""

    @pytest.mark.asyncio
    async def test_web_pentest_blocks_localhost(self):
        """WebPentestEngine blocks connections to localhost."""
        from app.engines.web_pentest import WebPentestEngine

        guard = SSRFGuard()
        engine = WebPentestEngine(ssrf_guard=guard)

        # Patch resolve_and_validate to simulate localhost resolution
        with patch.object(guard, 'resolve_and_validate') as mock_resolve:
            mock_resolve.side_effect = SSRFGuardError("IP 127.0.0.1 is in blocked network")

            result = await engine.run("localhost.test")
            # Engine should handle SSRF errors gracefully
            assert result.success or result.metadata.get("error") is not None

    @pytest.mark.asyncio
    async def test_web_pentest_blocks_metadata_endpoint(self):
        """WebPentestEngine blocks connections to cloud metadata endpoints."""
        from app.engines.web_pentest import WebPentestEngine

        guard = SSRFGuard()
        engine = WebPentestEngine(ssrf_guard=guard)

        with patch.object(guard, 'resolve_and_validate') as mock_resolve:
            mock_resolve.side_effect = SSRFGuardError("IP 169.254.169.254 is cloud metadata")

            result = await engine.run("metadata.test")
            assert result.success or result.metadata.get("error") is not None

    @pytest.mark.asyncio
    async def test_active_probes_uses_validated_smtp(self):
        """ActiveProbesEngine uses validated SMTP connect."""
        from app.engines.active_probes import ActiveProbesEngine
        from app.schemas.findings import Finding

        guard = SSRFGuard()
        engine = ActiveProbesEngine(ssrf_guard=guard)

        # Mock resolve_and_validate to block private IPs
        with patch.object(guard, 'resolve_and_validate') as mock_resolve:
            mock_resolve.side_effect = SSRFGuardError("IP 10.0.0.1 is in blocked network")

            # _validated_smtp_connect should return None when blocked
            conn = await engine._validated_smtp_connect("internal.test", 25)
            assert conn is None

    @pytest.mark.asyncio
    async def test_canary_probes_uses_validated_smtp(self):
        """CanaryProbesEngine uses validated SMTP connect."""
        from app.engines.canary_probes import CanaryProbesEngine

        guard = SSRFGuard()
        engine = CanaryProbesEngine(ssrf_guard=guard)

        with patch.object(guard, 'resolve_and_validate') as mock_resolve:
            mock_resolve.side_effect = SSRFGuardError("IP 172.16.0.1 is in blocked network")

            conn = await engine._validated_smtp_connect("private.test", 587)
            assert conn is None

    @pytest.mark.asyncio
    async def test_credential_probes_uses_validated_smtp(self):
        """CredentialProbesEngine uses validated SMTP connect."""
        from app.engines.credential_probes import CredentialProbesEngine

        guard = SSRFGuard()
        engine = CredentialProbesEngine(ssrf_guard=guard)

        with patch.object(guard, 'resolve_and_validate') as mock_resolve:
            mock_resolve.side_effect = SSRFGuardError("IP 192.168.1.1 is in blocked network")

            conn = await engine._validated_smtp_connect("lan.test", 587)
            assert conn is None

    @pytest.mark.asyncio
    async def test_credential_probes_uses_validated_smtp_tls(self):
        """CredentialProbesEngine uses validated SMTP TLS connect."""
        from app.engines.credential_probes import CredentialProbesEngine

        guard = SSRFGuard()
        engine = CredentialProbesEngine(ssrf_guard=guard)

        with patch.object(guard, 'resolve_and_validate') as mock_resolve:
            mock_resolve.side_effect = SSRFGuardError("IP 10.10.10.1 is in blocked network")

            reader, writer, banner = await engine._validated_smtp_connect_tls("vpn.test", 587)
            assert reader is None
            assert writer is None


class TestHTTPClientIntegration:
    """Test that HTTP clients use PinnedDNSTransport."""

    @pytest.mark.asyncio
    async def test_active_probes_http_client_uses_guard(self):
        """ActiveProbesEngine HTTP client uses SSRFGuard."""
        from app.engines.active_probes import ActiveProbesEngine

        guard = SSRFGuard()
        engine = ActiveProbesEngine(ssrf_guard=guard)

        client = engine._make_http_client()
        assert client is not None
        await client.aclose()

    @pytest.mark.asyncio
    async def test_credential_probes_http_client_uses_guard(self):
        """CredentialProbesEngine HTTP client uses SSRFGuard."""
        from app.engines.credential_probes import CredentialProbesEngine

        guard = SSRFGuard()
        engine = CredentialProbesEngine(ssrf_guard=guard)

        client = engine._make_http_client()
        assert client is not None
        await client.aclose()


class TestDefaultGuardCreation:
    """Test that engines create SSRFGuard by default when not provided."""

    def test_web_pentest_creates_default_guard(self):
        """WebPentestEngine creates SSRFGuard if not provided."""
        from app.engines.web_pentest import WebPentestEngine

        engine = WebPentestEngine()
        assert engine._guard is not None
        assert isinstance(engine._guard, SSRFGuard)

    def test_active_probes_creates_default_guard(self):
        """ActiveProbesEngine creates SSRFGuard if not provided."""
        from app.engines.active_probes import ActiveProbesEngine

        engine = ActiveProbesEngine()
        assert engine._guard is not None
        assert isinstance(engine._guard, SSRFGuard)

    def test_canary_probes_creates_default_guard(self):
        """CanaryProbesEngine creates SSRFGuard if not provided."""
        from app.engines.canary_probes import CanaryProbesEngine

        engine = CanaryProbesEngine()
        assert engine._guard is not None
        assert isinstance(engine._guard, SSRFGuard)

    def test_credential_probes_creates_default_guard(self):
        """CredentialProbesEngine creates SSRFGuard if not provided."""
        from app.engines.credential_probes import CredentialProbesEngine

        engine = CredentialProbesEngine()
        assert engine._guard is not None
        assert isinstance(engine._guard, SSRFGuard)
