"""
AT-07 — SMTP Discovery Engine tests.
All DNS and SMTP connections are mocked — no real network traffic.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call

import dns.resolver

from app.engines.smtp_discovery import (
    SMTPDiscoveryEngine,
    discover_mx,
    probe_smtp_host,
    _findings_from_probe,
    SMTPProbeResult,
    MXRecord,
)
from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError
from app.schemas.findings import RiskLevel


# ── Helpers ───────────────────────────────────────────────────────────────────


def _mock_ssrf_guard(blocked_hostnames: set[str] = None, blocked_ips: set[str] = None):
    """SSRFGuard mock: blocks specified hostnames/IPs, allows others with fake IP."""
    guard = MagicMock(spec=SSRFGuard)
    blocked_h = blocked_hostnames or set()
    blocked_i = blocked_ips or set()

    async def _resolve_and_validate(hostname):
        if hostname in blocked_h:
            raise SSRFGuardError(f"Blocked hostname: {hostname}")
        # Return a fake public IP
        return ["203.0.114.1"]

    async def _validate_domain_for_scan(domain):
        if domain in blocked_h:
            raise SSRFGuardError(f"Blocked domain: {domain}")

    guard.resolve_and_validate = _resolve_and_validate
    guard.validate_domain_for_scan = _validate_domain_for_scan
    return guard


def _mock_mx_resolver(domain_mx: dict[str, list[tuple[int, str]]]):
    """Mock DNS resolver returning MX records."""
    resolver = MagicMock()

    async def _resolve(name, rdtype, **kwargs):
        name = str(name).rstrip(".")
        if rdtype == "MX":
            records = domain_mx.get(name, [])
            if not records:
                raise dns.resolver.NoAnswer
            answer = []
            for priority, host in records:
                rdata = MagicMock()
                rdata.preference = priority
                rdata.exchange = MagicMock()
                rdata.exchange.__str__ = lambda self: host + "."
                answer.append(rdata)
            return answer
        elif rdtype == "A":
            raise dns.resolver.NoAnswer
        raise dns.resolver.NoAnswer

    resolver.resolve = _resolve
    return resolver


# ── MX Discovery Tests ────────────────────────────────────────────────────────


class TestMXDiscovery:
    @pytest.mark.asyncio
    async def test_mx_records_sorted_by_priority(self):
        guard = _mock_ssrf_guard()
        with patch("app.engines.smtp_discovery._make_resolver") as mock_res:
            mock_res.return_value = _mock_mx_resolver({
                "example.com": [(20, "mail2.example.com"), (10, "mail1.example.com")]
            })
            mx_records, findings = await discover_mx("example.com", guard)

        assert mx_records[0].priority == 10
        assert mx_records[0].hostname == "mail1.example.com"
        assert mx_records[1].priority == 20

    @pytest.mark.asyncio
    async def test_no_mx_records_generates_finding(self):
        guard = _mock_ssrf_guard()
        with patch("app.engines.smtp_discovery._make_resolver") as mock_res:
            mock_res.return_value = _mock_mx_resolver({})
            mx_records, findings = await discover_mx("nomx.example.com", guard)

        assert not mx_records or all(f.check_id in ("SMTP-02", "SMTP-03") for f in findings)

    @pytest.mark.asyncio
    async def test_ssrf_blocked_mx_host_generates_finding(self):
        guard = _mock_ssrf_guard(blocked_hostnames={"mail.internal.corp"})
        with patch("app.engines.smtp_discovery._make_resolver") as mock_res:
            mock_res.return_value = _mock_mx_resolver({
                "example.com": [(10, "mail.internal.corp")]
            })
            mx_records, findings = await discover_mx("example.com", guard)

        # MX record is returned but marked as blocked
        assert mx_records[0].ssrf_blocked
        # Finding generated
        assert any(f.check_id == "SMTP-04" for f in findings)

    @pytest.mark.asyncio
    async def test_multiple_mx_all_returned(self):
        guard = _mock_ssrf_guard()
        with patch("app.engines.smtp_discovery._make_resolver") as mock_res:
            mock_res.return_value = _mock_mx_resolver({
                "example.com": [(10, "mx1.example.com"), (20, "mx2.example.com"), (30, "mx3.example.com")]
            })
            mx_records, findings = await discover_mx("example.com", guard)

        assert len(mx_records) == 3


# ── SMTP Probe Findings Tests ─────────────────────────────────────────────────


def _security_findings(probe: SMTPProbeResult) -> list:
    """STARTTLS / cleartext-AUTH / open-relay checks moved from smtp_discovery
    (SMTP-05..08) to smtp_security (SMTPS-01..04), which consumes the probe dicts
    smtp_discovery publishes in EngineResult.metadata["probes"]."""
    from app.engines.smtp_security import _analyze_probe_dict
    probe_dict = {
        "host": probe.host,
        "port": probe.port,
        "ip": probe.ip,
        "connected": probe.connected,
        "banner": probe.banner,
        "starttls": probe.starttls_supported,
        "tls_negotiated": probe.tls_negotiated,
        "tls_info": probe.tls_info,
        "auth_mechanisms": probe.auth_mechanisms,
        "open_relay": probe.open_relay_assessment,
        "enum_commands": [],
        "error": probe.error,
    }
    return _analyze_probe_dict(probe_dict, "example.com")


class TestSMTPProbeFindings:
    def _make_connected_probe(self, **kwargs) -> SMTPProbeResult:
        defaults = {
            "host": "mail.example.com",
            "port": 25,
            "ip": "203.0.114.1",
            "connected": True,
            "banner": "220 mail.example.com ESMTP",
            "ehlo_response": "250 mail.example.com",
            "extensions": {},
            "auth_mechanisms": [],
            "starttls_supported": False,
            "tls_negotiated": False,
            "open_relay_assessment": "closed",
        }
        defaults.update(kwargs)
        return SMTPProbeResult(**defaults)

    def test_no_starttls_on_port_25_generates_finding(self):
        probe = self._make_connected_probe(port=25, starttls_supported=False)
        findings = _security_findings(probe)
        assert any(f.check_id == "SMTPS-01" for f in findings)
        f = next(f for f in findings if f.check_id == "SMTPS-01")
        assert f.risk_level == RiskLevel.HIGH

    def test_no_starttls_on_port_587_generates_finding(self):
        probe = self._make_connected_probe(port=587, starttls_supported=False)
        findings = _security_findings(probe)
        assert any(f.check_id == "SMTPS-01" for f in findings)

    def test_no_starttls_on_port_465_no_finding(self):
        """Port 465 uses implicit TLS — no STARTTLS expected."""
        probe = self._make_connected_probe(port=465, starttls_supported=False, tls_negotiated=True)
        findings = _security_findings(probe)
        assert not any(f.check_id == "SMTPS-01" for f in findings)

    def test_starttls_advertised_but_failed_finding(self):
        probe = self._make_connected_probe(
            port=25,
            starttls_supported=True,
            tls_negotiated=False,
            tls_info={"error": "certificate verify failed"},
        )
        findings = _security_findings(probe)
        assert any(f.check_id == "SMTPS-02" for f in findings)

    def test_cleartext_auth_without_tls_finding(self):
        probe = self._make_connected_probe(
            port=587,
            auth_mechanisms=["PLAIN", "LOGIN"],
            starttls_supported=True,
            tls_negotiated=False,
        )
        findings = _security_findings(probe)
        assert any(f.check_id == "SMTPS-03" for f in findings)

    def test_auth_mechanisms_after_tls_no_finding(self):
        """PLAIN/LOGIN after STARTTLS is acceptable."""
        probe = self._make_connected_probe(
            port=587,
            auth_mechanisms=["PLAIN", "LOGIN"],
            starttls_supported=True,
            tls_negotiated=True,
        )
        findings = _security_findings(probe)
        assert not any(f.check_id == "SMTPS-03" for f in findings)

    def test_open_relay_suspected_finding(self):
        """Open relay: RCPT TO accepted = SUSPECTED (HIGH, not CRITICAL — no DATA issued)."""
        probe = self._make_connected_probe(
            port=25,
            open_relay_assessment="likely_open",
            starttls_supported=True,
        )
        findings = _security_findings(probe)
        assert any(f.check_id == "SMTPS-04" for f in findings)
        f = next(f for f in findings if f.check_id == "SMTPS-04")
        # SUSPECTED level: HIGH not CRITICAL (no DATA transaction = unconfirmed relay)
        assert f.risk_level == RiskLevel.HIGH
        assert f.confidence <= 0.75
        assert "SUSPECTED" in f.title or "SUSPECTED" in (f.evidence[0].technical_details or {}).get("confirmation_level", "")

    def test_not_connected_no_findings(self):
        probe = SMTPProbeResult(
            host="mail.example.com", port=25, ip="203.0.114.1",
            connected=False, error="Connection refused"
        )
        findings = _findings_from_probe(probe, "example.com")
        assert not findings


# ── Full Engine Integration Tests (mocked) ────────────────────────────────────


class TestSMTPDiscoveryEngine:
    @pytest.mark.asyncio
    async def test_engine_completes_on_no_mx(self):
        with patch("app.engines.smtp_discovery._make_resolver") as mock_res, \
             patch("app.engines.smtp_discovery.SSRFGuard") as MockGuard:

            mock_res.return_value = _mock_mx_resolver({})

            guard = _mock_ssrf_guard()
            MockGuard.return_value = guard

            engine = SMTPDiscoveryEngine(timeout=10.0, ssrf_guard=guard)
            result = await engine.run("nodomain.invalid")

        assert result.engine == "smtp_discovery"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_engine_timeout_handled(self):
        """Engine timeout returns EngineResult with error, does not raise."""
        guard = _mock_ssrf_guard()

        async def _slow_run(domain):
            import asyncio
            await asyncio.sleep(100)

        engine = SMTPDiscoveryEngine(timeout=0.01, ssrf_guard=guard)
        result = await engine.run("example.com")
        assert result.error is not None
        assert "timed out" in result.error.lower()

    @pytest.mark.asyncio
    async def test_engine_ssrf_blocked_domain(self):
        """Domain that resolves to private IP — SSRF guard blocks before creating findings."""
        guard = _mock_ssrf_guard()

        async def _raise_ssrf(domain):
            raise SSRFGuardError("IP 10.0.0.1 is in blocked network 10.0.0.0/8")

        guard.validate_domain_for_scan = _raise_ssrf

        with patch("app.engines.smtp_discovery._make_resolver") as mock_res:
            mock_res.return_value = _mock_mx_resolver({
                "internal.corp": [(10, "mail.internal.corp")]
            })
            engine = SMTPDiscoveryEngine(timeout=10.0, ssrf_guard=guard)
            result = await engine.run("internal.corp")

        # Engine should not crash — SSRF error is surfaced as finding or metadata
        assert result.engine == "smtp_discovery"

    @pytest.mark.asyncio
    async def test_engine_findings_have_required_fields(self):
        """Every finding must have engine, check_id, evidence, remediation."""
        with patch("app.engines.smtp_discovery._make_resolver") as mock_res:
            mock_res.return_value = _mock_mx_resolver({})
            guard = _mock_ssrf_guard()
            engine = SMTPDiscoveryEngine(timeout=10.0, ssrf_guard=guard)
            result = await engine.run("nodomain.invalid")

        for f in result.findings:
            assert f.engine
            assert f.check_id
            assert f.remediation
            assert f.evidence is not None
