"""
AT-08 — DNS Authentication Engine tests.
All DNS calls are mocked — no real network traffic.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver

from app.engines.dns_auth import (
    DMARCAnalyser,
    DKIMAnalyser,
    DNSAuthEngine,
    SPFAnalyser,
    _make_resolver,
)
from app.schemas.findings import RiskLevel


# ── Helpers ───────────────────────────────────────────────────────────────────


def _mock_resolver_with_txt(records: dict[str, list[str]]):
    """
    Returns a mock resolver whose resolve() returns pre-defined TXT records.
    records: { "hostname": ["txt1", "txt2"] }
    """
    resolver = MagicMock()

    async def _resolve(name, rdtype, **kwargs):
        name = str(name).rstrip(".")
        if rdtype != "TXT":
            raise dns.resolver.NoAnswer
        txts = records.get(name, [])
        if not txts:
            raise dns.resolver.NoAnswer
        # Build mock rdata objects
        answer = []
        for txt in txts:
            rdata = MagicMock()
            rdata.strings = [txt.encode("utf-8")]
            answer.append(rdata)
        return answer

    resolver.resolve = _resolve
    return resolver


# ── SPF Tests ─────────────────────────────────────────────────────────────────


class TestSPF:
    @pytest.mark.asyncio
    async def test_spf_absent(self):
        resolver = _mock_resolver_with_txt({})
        analyser = SPFAnalyser(resolver)
        result = await analyser.analyse("nodomain.invalid")
        assert any(f.check_id == "SPF-01" for f in result.findings)
        assert any(f.risk_level == RiskLevel.HIGH for f in result.findings)

    @pytest.mark.asyncio
    async def test_spf_plus_all_critical(self):
        resolver = _mock_resolver_with_txt({"example.com": ["v=spf1 +all"]})
        analyser = SPFAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "SPF-03" for f in result.findings)
        f = next(f for f in result.findings if f.check_id == "SPF-03")
        assert f.risk_level == RiskLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_spf_softfail_medium(self):
        resolver = _mock_resolver_with_txt({"example.com": ["v=spf1 include:_spf.google.com ~all"]})
        analyser = SPFAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "SPF-04" for f in result.findings)
        f = next(f for f in result.findings if f.check_id == "SPF-04")
        assert f.risk_level == RiskLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_spf_reject_all_no_finding(self):
        """SPF with -all should produce no 'all' qualifier finding."""
        resolver = _mock_resolver_with_txt({"example.com": ["v=spf1 include:_spf.google.com -all"]})
        analyser = SPFAnalyser(resolver)
        result = await analyser.analyse("example.com")
        # No SPF-03 (critical), no SPF-04 (medium) for the qualifier
        qualifier_findings = [f for f in result.findings if f.check_id in ("SPF-03", "SPF-04", "SPF-05")]
        assert not qualifier_findings
        assert result.all_qualifier == "-"

    @pytest.mark.asyncio
    async def test_spf_no_all_mechanism_finding(self):
        resolver = _mock_resolver_with_txt({"example.com": ["v=spf1 ip4:1.2.3.4"]})
        analyser = SPFAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "SPF-05" for f in result.findings)

    @pytest.mark.asyncio
    async def test_spf_multiple_records_permerror(self):
        resolver = _mock_resolver_with_txt({
            "example.com": ["v=spf1 -all", "v=spf1 ip4:1.2.3.4 -all"]
        })
        analyser = SPFAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "SPF-02" for f in result.findings)
        assert result.has_permerror

    @pytest.mark.asyncio
    async def test_spf_lookup_limit_exceeded(self):
        """12 include: mechanisms exceeds the 10-lookup limit."""
        # Build a chain of includes
        records = {}
        # Main record with 11 includes — exceeds limit
        includes = " ".join(f"include:sub{i}.example.com" for i in range(11))
        records["example.com"] = [f"v=spf1 {includes} -all"]
        for i in range(11):
            records[f"sub{i}.example.com"] = [f"v=spf1 ip4:1.2.3.{i} -all"]

        resolver = _mock_resolver_with_txt(records)
        analyser = SPFAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert result.exceeded_lookup_limit
        assert any(f.check_id == "SPF-06" for f in result.findings)

    @pytest.mark.asyncio
    async def test_spf_neutral_all_finding(self):
        """?all (neutral) should produce a finding — no enforcement."""
        resolver = _mock_resolver_with_txt({"example.com": ["v=spf1 ip4:1.2.3.4 ?all"]})
        analyser = SPFAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "SPF-05b" for f in result.findings)
        f = next(f for f in result.findings if f.check_id == "SPF-05b")
        assert f.risk_level == RiskLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_spf_cycle_detection(self):
        """SPF include cycle (A includes B includes A) should not loop infinitely."""
        # A includes B, B includes A — cycle
        records = {
            "a.example.com": ["v=spf1 include:b.example.com -all"],
            "b.example.com": ["v=spf1 include:a.example.com -all"],
        }
        resolver = _mock_resolver_with_txt(records)
        analyser = SPFAnalyser(resolver)
        # Should complete without hanging, cycle detected → permerror
        result = await analyser.analyse("a.example.com")
        assert result.has_permerror

    @pytest.mark.asyncio
    async def test_spf_temperror_handling(self):
        """DNS timeout during include resolution → temperror finding."""
        resolver = MagicMock()

        async def _resolve_with_timeout(name, rdtype, **kwargs):
            name = str(name)
            if name == "example.com":
                rdata = MagicMock()
                rdata.strings = [b"v=spf1 include:external.com -all"]
                return [rdata]
            raise dns.exception.Timeout

        resolver.resolve = _resolve_with_timeout
        analyser = SPFAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert result.has_temperror
        assert any(f.check_id == "SPF-07" for f in result.findings)


# ── DKIM Tests ────────────────────────────────────────────────────────────────


class TestDKIM:
    @pytest.mark.asyncio
    async def test_dkim_no_selectors_found_info(self):
        resolver = _mock_resolver_with_txt({})
        analyser = DKIMAnalyser(resolver, selectors=["default", "selector1"])
        _, findings = await analyser.analyse("nodomain.invalid")
        assert any(f.check_id == "DKIM-01" for f in findings)
        f = next(f for f in findings if f.check_id == "DKIM-01")
        # Absence of discovery ≠ HIGH — it's INFO (undiscoverable selectors)
        assert f.risk_level == RiskLevel.INFO

    @pytest.mark.asyncio
    async def test_dkim_valid_selector_found(self):
        """A valid DKIM record for a known selector — no finding."""
        # Minimal valid DKIM record (RSA-2048 would have a long p= but we just test parsing)
        record = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
        resolver = _mock_resolver_with_txt({
            "selector1._domainkey.example.com": [record]
        })
        analyser = DKIMAnalyser(resolver, selectors=["selector1"])
        selector_results, findings = await analyser.analyse("example.com")
        assert any(r.found for r in selector_results)
        # No DKIM-01 (no-selector finding) since we found one
        assert not any(f.check_id == "DKIM-01" for f in findings)

    @pytest.mark.asyncio
    async def test_dkim_revoked_key_finding(self):
        """p= empty → revoked key."""
        record = "v=DKIM1; k=rsa; p="
        resolver = _mock_resolver_with_txt({
            "default._domainkey.example.com": [record]
        })
        analyser = DKIMAnalyser(resolver, selectors=["default"])
        _, findings = await analyser.analyse("example.com")
        assert any(f.check_id == "DKIM-02" for f in findings)


# ── DMARC Tests ───────────────────────────────────────────────────────────────


class TestDMARC:
    @pytest.mark.asyncio
    async def test_dmarc_absent(self):
        resolver = _mock_resolver_with_txt({})
        analyser = DMARCAnalyser(resolver)
        result = await analyser.analyse("nodomain.invalid")
        assert any(f.check_id == "DMARC-01" for f in result.findings)
        f = next(f for f in result.findings if f.check_id == "DMARC-01")
        assert f.risk_level == RiskLevel.HIGH

    @pytest.mark.asyncio
    async def test_dmarc_p_none_medium(self):
        record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        resolver = _mock_resolver_with_txt({"_dmarc.example.com": [record]})
        analyser = DMARCAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "DMARC-04" for f in result.findings)
        f = next(f for f in result.findings if f.check_id == "DMARC-04")
        assert f.risk_level == RiskLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_dmarc_p_quarantine_low(self):
        record = "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"
        resolver = _mock_resolver_with_txt({"_dmarc.example.com": [record]})
        analyser = DMARCAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "DMARC-05" for f in result.findings)
        f = next(f for f in result.findings if f.check_id == "DMARC-05")
        assert f.risk_level == RiskLevel.LOW

    @pytest.mark.asyncio
    async def test_dmarc_p_reject_no_policy_finding(self):
        record = "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"
        resolver = _mock_resolver_with_txt({"_dmarc.example.com": [record]})
        analyser = DMARCAnalyser(resolver)
        result = await analyser.analyse("example.com")
        # p=reject should not trigger a policy degradation finding
        assert not any(f.check_id in ("DMARC-04", "DMARC-05") for f in result.findings)

    @pytest.mark.asyncio
    async def test_dmarc_no_rua_finding(self):
        record = "v=DMARC1; p=reject; pct=100"
        resolver = _mock_resolver_with_txt({"_dmarc.example.com": [record]})
        analyser = DMARCAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "DMARC-06" for f in result.findings)

    @pytest.mark.asyncio
    async def test_dmarc_pct_partial_finding(self):
        record = "v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com"
        resolver = _mock_resolver_with_txt({"_dmarc.example.com": [record]})
        analyser = DMARCAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "DMARC-07" for f in result.findings)

    @pytest.mark.asyncio
    async def test_dmarc_multiple_records(self):
        resolver = _mock_resolver_with_txt({
            "_dmarc.example.com": [
                "v=DMARC1; p=none",
                "v=DMARC1; p=reject",
            ]
        })
        analyser = DMARCAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "DMARC-02" for f in result.findings)

    @pytest.mark.asyncio
    async def test_dmarc_invalid_syntax_no_p(self):
        """Record without p= tag → DMARC-03."""
        record = "v=DMARC1; rua=mailto:dmarc@example.com"
        resolver = _mock_resolver_with_txt({"_dmarc.example.com": [record]})
        analyser = DMARCAnalyser(resolver)
        result = await analyser.analyse("example.com")
        assert any(f.check_id == "DMARC-03" for f in result.findings)


# ── Full Engine Tests ─────────────────────────────────────────────────────────


class TestDNSAuthEngine:
    @pytest.mark.asyncio
    async def test_engine_completes_without_error(self):
        """Engine wraps analyser calls and returns a result with no crash."""
        with patch("app.engines.dns_auth._make_resolver") as mock_make:
            mock_make.return_value = _mock_resolver_with_txt({})
            engine = DNSAuthEngine(timeout=10.0)
            result = await engine.run("nodomain.invalid")
        assert result.engine == "dns_auth"
        assert result.error is None  # engine-level error should be None even with no records

    @pytest.mark.asyncio
    async def test_engine_findings_serializable(self):
        """All finding evidence must be JSON-serializable (for DB storage)."""
        import json
        with patch("app.engines.dns_auth._make_resolver") as mock_make:
            mock_make.return_value = _mock_resolver_with_txt({})
            engine = DNSAuthEngine(timeout=10.0)
            result = await engine.run("nodomain.invalid")
        for finding in result.findings:
            for evidence in finding.evidence:
                # Should not raise
                json.dumps(evidence.model_dump(mode="json"))
