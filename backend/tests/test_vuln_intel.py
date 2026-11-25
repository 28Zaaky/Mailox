"""
VulnIntelEngine tests.
All CVE lookups use the local DB; no real NVD API calls.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.engines.vuln_intel import CVEConfidence, VulnIntelEngine
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_engine():
    return VulnIntelEngine(timeout=30.0)


def _make_webmail_finding(product: str, version: str | None = None) -> Finding:
    """Minimal WM-001 finding that VulnIntelEngine will parse."""
    return Finding(
        engine="webmail",
        check_id="WM-001",
        title=f"Webmail interface identified: {product}",
        description=f"{product} detected.",
        risk_level=RiskLevel.INFO,
        confidence=0.9,
        evidence=[Evidence(
            type=EvidenceType.HTTP_RESPONSE,
            observed_value=f"HTTP 200",
            source="https://webmail.example.com/",
            technical_details={
                "product": product,
                "version": version,
                "confidence": 0.9,
                "fingerprint_signals": [],
                "redirect_chain": [],
                "source_engine": "webmail",
            },
        )],
        remediation="",
        affected_asset="webmail.example.com",
    )


# ── Software extraction ────────────────────────────────────────────────────────


class TestSoftwareExtraction:
    def test_extracts_product_from_wm001(self):
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.6.2")
        matches = engine._extract_software([f])
        assert len(matches) == 1
        assert matches[0].product == "Roundcube"
        assert matches[0].version == "1.6.2"

    def test_ignores_non_wm001(self):
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.6.2")
        f.check_id = "WM-SEC-HSTS"
        matches = engine._extract_software([f])
        assert len(matches) == 0

    def test_deduplicates_same_product_version(self):
        engine = _make_engine()
        f1 = _make_webmail_finding("Roundcube", "1.6.2")
        f2 = _make_webmail_finding("Roundcube", "1.6.2")
        matches = engine._extract_software([f1, f2])
        assert len(matches) == 1

    def test_no_findings_returns_empty(self):
        engine = _make_engine()
        assert engine._extract_software([]) == []


# ── Semver parsing ─────────────────────────────────────────────────────────────


class TestSemverParsing:
    def test_parse_three_part(self):
        engine = _make_engine()
        # _parse_semver always returns 4-tuples for consistent cross-version comparison
        assert engine._parse_semver("1.6.3") == (1, 6, 3, 0)

    def test_parse_two_part(self):
        engine = _make_engine()
        assert engine._parse_semver("1.6") == (1, 6, 0, 0)

    def test_parse_one_part(self):
        engine = _make_engine()
        assert engine._parse_semver("2") == (2, 0, 0, 0)

    def test_parse_invalid_returns_none(self):
        engine = _make_engine()
        assert engine._parse_semver("Exchange Server 2019") is None

    def test_comparison_lt(self):
        engine = _make_engine()
        v = engine._parse_semver("1.6.2")
        assert engine._single_constraint(v, "< 1.6.3") is True
        assert engine._single_constraint(v, "< 1.6.2") is False

    def test_comparison_gte(self):
        engine = _make_engine()
        v = engine._parse_semver("1.5.0")
        assert engine._single_constraint(v, ">= 1.5.0") is True
        assert engine._single_constraint(v, ">= 1.5.1") is False


# ── Version range checks ───────────────────────────────────────────────────────


class TestVersionRangeCheck:
    def test_confirmed_in_range(self):
        engine = _make_engine()
        # CVE-2023-43770: affected < 1.6.3
        result = engine._check_version_range(
            "1.6.2",
            ["< 1.4.14", ">=1.5.0, < 1.5.4", ">=1.6.0, < 1.6.3"],
            ["1.4.14", "1.5.4", "1.6.3"],
        )
        assert result == CVEConfidence.CONFIRMED

    def test_not_affected_patched(self):
        engine = _make_engine()
        result = engine._check_version_range(
            "1.6.3",
            ["< 1.4.14", ">=1.5.0, < 1.5.4", ">=1.6.0, < 1.6.3"],
            ["1.4.14", "1.5.4", "1.6.3"],
        )
        assert result == CVEConfidence.NOT_AFFECTED

    def test_unknown_version_returns_potentially(self):
        engine = _make_engine()
        result = engine._check_version_range(
            "Exchange 2019 CU7",
            ["Exchange Server 2019 CU7/CU8"],
            ["March 2021 Security Update"],
        )
        assert result == CVEConfidence.POTENTIALLY


# ── Local CVE DB correlation ───────────────────────────────────────────────────


class TestLocalCVEDB:
    @pytest.mark.asyncio
    async def test_roundcube_cves_found(self):
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.6.2")
        result = await engine.run_from_findings("example.com", [f])
        # CVE-2023-43770 affects < 1.6.3 — should appear
        cve_ids = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if ev.technical_details and "cve_id" in ev.technical_details
        ]
        assert "CVE-2023-43770" in cve_ids

    @pytest.mark.asyncio
    async def test_roundcube_patched_no_finding(self):
        engine = _make_engine()
        # 1.6.8 is past all patched versions in local DB
        f = _make_webmail_finding("Roundcube", "1.6.8")
        result = await engine.run_from_findings("example.com", [f])
        # All known Roundcube CVEs should be NOT_AFFECTED → no CVE finding.
        # Updated: only the INFO "VI-CLEAN-ROUNDCUBE" summary may remain.
        assert not [fi for fi in result.findings if fi.check_id.startswith("VI-CVE-")]
        assert all(
            fi.check_id == "VI-CLEAN-ROUNDCUBE" and fi.risk_level == RiskLevel.INFO
            for fi in result.findings
        )

    @pytest.mark.asyncio
    async def test_zimbra_cve_critical(self):
        engine = _make_engine()
        # CVE-2024-45519: Zimbra CRITICAL — any unpatched version
        f = _make_webmail_finding("Zimbra", "10.0.8")
        result = await engine.run_from_findings("example.com", [f])
        risk_levels = [finding.risk_level for finding in result.findings]
        assert RiskLevel.CRITICAL in risk_levels

    @pytest.mark.asyncio
    async def test_unknown_product_no_findings(self):
        engine = _make_engine()
        f = _make_webmail_finding("RainLoop", "1.16.0")
        result = await engine.run_from_findings("example.com", [f])
        # RainLoop not in local DB — no CVE findings
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_no_prior_findings_returns_note(self):
        engine = _make_engine()
        result = await engine.run_from_findings("example.com", [])
        assert "note" in result.metadata

    @pytest.mark.asyncio
    async def test_standalone_run_returns_note(self):
        engine = _make_engine()
        result = await engine.run("example.com")
        assert "note" in result.metadata

    @pytest.mark.asyncio
    async def test_cisa_kev_flagged_in_finding(self):
        engine = _make_engine()
        # CVE-2023-43770 is in CISA KEV
        f = _make_webmail_finding("Roundcube", "1.6.2")
        result = await engine.run_from_findings("example.com", [f])
        kev_findings = [
            fi for fi in result.findings
            if any(
                ev.technical_details and ev.technical_details.get("in_cisa_kev")
                for ev in fi.evidence
            )
        ]
        assert len(kev_findings) > 0


# ── Finding structure ──────────────────────────────────────────────────────────


class TestFindingStructure:
    @pytest.mark.asyncio
    async def test_finding_has_required_fields(self):
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.6.2")
        result = await engine.run_from_findings("example.com", [f])
        assert len(result.findings) > 0
        for finding in result.findings:
            assert finding.check_id.startswith("VI-CVE-")
            assert finding.title
            assert finding.description
            assert finding.remediation
            assert len(finding.evidence) > 0

    @pytest.mark.asyncio
    async def test_roundcube_14x_confirmed_for_cve_2024_37383(self):
        """
        Roundcube 1.4.14 IS affected by CVE-2024-37383.
        OSV range: Introduced 0 (all versions before 1.5.7) — no lower bound.
        Source: https://osv.dev/vulnerability/CVE-2024-37383
        """
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.4.14")
        result = await engine.run_from_findings("example.com", [f])
        cve_ids_confirmed = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if (
                ev.technical_details
                and ev.technical_details.get("cve_id") == "CVE-2024-37383"
                and ev.technical_details.get("confidence") == "confirmed"
            )
        ]
        assert "CVE-2024-37383" in cve_ids_confirmed, (
            "Roundcube 1.4.14 is in the < 1.5.7 range (OSV: introduced=0) "
            "and must be CONFIRMED for CVE-2024-37383"
        )

    @pytest.mark.asyncio
    async def test_roundcube_14x_confirmed_for_cve_2024_42009(self):
        """
        Roundcube 1.4.14 IS affected by CVE-2024-42009.
        OSV range: Introduced 0 — no lower bound on 1.5 branch.
        Source: https://osv.dev/vulnerability/CVE-2024-42009
        """
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.4.14")
        result = await engine.run_from_findings("example.com", [f])
        cve_ids_confirmed = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if (
                ev.technical_details
                and ev.technical_details.get("cve_id") == "CVE-2024-42009"
                and ev.technical_details.get("confidence") == "confirmed"
            )
        ]
        assert "CVE-2024-42009" in cve_ids_confirmed

    @pytest.mark.asyncio
    async def test_roundcube_15x_confirmed_for_cve_2024_37383(self):
        """Roundcube 1.5.6 is in '< 1.5.7' range → CONFIRMED."""
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.5.6")
        result = await engine.run_from_findings("example.com", [f])
        cve_ids_confirmed = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if (
                ev.technical_details
                and ev.technical_details.get("cve_id") == "CVE-2024-37383"
                and ev.technical_details.get("confidence") == "confirmed"
            )
        ]
        assert "CVE-2024-37383" in cve_ids_confirmed

    @pytest.mark.asyncio
    async def test_roundcube_157_not_affected_cve_2024_37383(self):
        """Roundcube 1.5.7 is the patched version → NOT_AFFECTED."""
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.5.7")
        result = await engine.run_from_findings("example.com", [f])
        cve_ids_confirmed = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if (
                ev.technical_details
                and ev.technical_details.get("cve_id") == "CVE-2024-37383"
                and ev.technical_details.get("confidence") == "confirmed"
            )
        ]
        assert "CVE-2024-37383" not in cve_ids_confirmed

    @pytest.mark.asyncio
    async def test_roundcube_160_confirmed_for_cve_2024_37383(self):
        """Roundcube 1.6.0 is in '>=1.6.0, < 1.6.7' range → CONFIRMED."""
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.6.0")
        result = await engine.run_from_findings("example.com", [f])
        cve_ids_confirmed = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if (
                ev.technical_details
                and ev.technical_details.get("cve_id") == "CVE-2024-37383"
                and ev.technical_details.get("confidence") == "confirmed"
            )
        ]
        assert "CVE-2024-37383" in cve_ids_confirmed

    @pytest.mark.asyncio
    async def test_roundcube_166_confirmed_for_cve_2024_37383(self):
        """Roundcube 1.6.6 is in '>=1.6.0, < 1.6.7' range → CONFIRMED."""
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.6.6")
        result = await engine.run_from_findings("example.com", [f])
        cve_ids_confirmed = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if (
                ev.technical_details
                and ev.technical_details.get("cve_id") == "CVE-2024-37383"
                and ev.technical_details.get("confidence") == "confirmed"
            )
        ]
        assert "CVE-2024-37383" in cve_ids_confirmed

    @pytest.mark.asyncio
    async def test_roundcube_167_not_affected_cve_2024_37383(self):
        """Roundcube 1.6.7 is the patched version → NOT_AFFECTED."""
        engine = _make_engine()
        f = _make_webmail_finding("Roundcube", "1.6.7")
        result = await engine.run_from_findings("example.com", [f])
        cve_ids_confirmed = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if (
                ev.technical_details
                and ev.technical_details.get("cve_id") == "CVE-2024-37383"
                and ev.technical_details.get("confidence") == "confirmed"
            )
        ]
        assert "CVE-2024-37383" not in cve_ids_confirmed

    @pytest.mark.asyncio
    async def test_confidence_confirmed_vs_potentially(self):
        engine = _make_engine()
        # With version 1.6.2 — CONFIRMED affected by CVE-2023-43770
        f_confirmed = _make_webmail_finding("Roundcube", "1.6.2")
        result_confirmed = await engine.run_from_findings("example.com", [f_confirmed])

        # Without version — POTENTIALLY
        f_potentially = _make_webmail_finding("Roundcube", None)
        result_potentially = await engine.run_from_findings("example.com", [f_potentially])

        if result_confirmed.findings and result_potentially.findings:
            # confirmed confidence should be higher than potentially
            conf_c = result_confirmed.findings[0].confidence
            conf_p = result_potentially.findings[0].confidence
            assert conf_c >= conf_p
