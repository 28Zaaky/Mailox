"""
Security hardening tests.

Covers the specific vulnerabilities and accuracy issues fixed in Phase 4.1:
- SSRF bypass via redirect (WM-SSRF-REDIRECT)
- TLS certificate error findings (WM-TLS-CERT)
- Cookie security findings (WM-COOKIE-*)
- Zimbra 4-component version parsing
- Exchange OWA build number CVE matching
- _aggregate_confidence correct behavior (per-CVE confidence tracking)
- Roundcube NOT_AFFECTED when truly patched
"""
import ssl
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import httpx

from app.engines.webmail import WebmailEngine, WebmailEndpoint
from app.engines.vuln_intel import CVEConfidence, VulnIntelEngine
from app.engines.base import EngineResult
from app.engines.ssrf_guard import SSRFGuardError
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_wm_engine():
    return WebmailEngine(timeout=30.0)


def _make_vi_engine():
    return VulnIntelEngine(timeout=30.0)


def _make_webmail_finding(product: str, version: str | None = None) -> Finding:
    return Finding(
        engine="webmail",
        check_id="WM-001",
        title=f"Webmail interface identified: {product}",
        description=f"{product} detected.",
        risk_level=RiskLevel.INFO,
        confidence=0.9,
        evidence=[Evidence(
            type=EvidenceType.HTTP_RESPONSE,
            observed_value="HTTP 200",
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


def _make_endpoint(
    product="Roundcube",
    version="1.6.2",
    confidence=0.9,
    headers=None,
    url="https://webmail.example.com/roundcube/",
):
    return WebmailEndpoint(
        url=url,
        product=product,
        version=version,
        confidence=confidence,
        status_code=200,
        headers=headers or {},
        fingerprint_signals=["body:rcmlogon"],
    )


# ── SSRF via Redirect ──────────────────────────────────────────────────────────


class TestSSRFRedirectProtection:
    @pytest.mark.asyncio
    async def test_ssrf_hook_blocks_redirect_to_private_ip(self):
        """
        _ssrf_redirect_hook must raise SSRFGuardError when a redirect target
        resolves to a private IP, preventing SSRF bypass via open redirects.
        """
        engine = _make_wm_engine()

        # Simulate SSRFGuard blocking a private-IP destination
        with patch.object(
            engine._ssrf_guard,
            "validate_domain_for_scan",
            side_effect=SSRFGuardError("private IP"),
        ) as mock_guard:
            fake_request = MagicMock(spec=httpx.Request)
            fake_request.url = MagicMock()
            fake_request.url.host = "169.254.169.254"

            with pytest.raises(SSRFGuardError):
                await engine._ssrf_redirect_hook(fake_request)

            mock_guard.assert_called_once_with("169.254.169.254")

    @pytest.mark.asyncio
    async def test_ssrf_hook_allows_valid_host(self):
        """Hook must NOT raise for valid external hosts."""
        engine = _make_wm_engine()

        with patch.object(
            engine._ssrf_guard,
            "validate_domain_for_scan",
            new_callable=AsyncMock,  # returns None — no exception
        ):
            fake_request = MagicMock(spec=httpx.Request)
            fake_request.url = MagicMock()
            fake_request.url.host = "webmail.example.com"

            await engine._ssrf_redirect_hook(fake_request)  # must not raise

    @pytest.mark.asyncio
    async def test_ssrf_hook_ignores_empty_host(self):
        """Hook must not call validate when host is empty (e.g. data: URIs)."""
        engine = _make_wm_engine()

        with patch.object(
            engine._ssrf_guard,
            "validate_domain_for_scan",
            new_callable=AsyncMock,
        ) as mock_guard:
            fake_request = MagicMock(spec=httpx.Request)
            fake_request.url = MagicMock()
            fake_request.url.host = ""

            await engine._ssrf_redirect_hook(fake_request)
            mock_guard.assert_not_called()

    @pytest.mark.asyncio
    async def test_probe_url_catches_ssrf_guard_error(self):
        """
        When _ssrf_redirect_hook raises SSRFGuardError inside a redirect chain,
        _probe_url must catch it and return None (not propagate).
        """
        engine = _make_wm_engine()

        async with httpx.AsyncClient() as real_client:
            mock_client = MagicMock(spec=httpx.AsyncClient)
            mock_client.get = AsyncMock(side_effect=SSRFGuardError("redirect blocked"))

            result = await engine._probe_url(
                mock_client,
                "https://webmail.example.com/roundcube/",
                "Roundcube",
                0.5,
            )

        assert result is None


# ── TLS Certificate Findings ───────────────────────────────────────────────────


class TestTLSCertificateFindings:
    @pytest.mark.asyncio
    async def test_check_tls_host_valid_cert_returns_none(self):
        """When cert validation succeeds, _check_tls_host must return None."""
        engine = _make_wm_engine()

        with patch.object(engine._ssrf_guard, "validate_domain_for_scan", new_callable=AsyncMock):
            with patch("httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.head = AsyncMock(return_value=MagicMock(status_code=200))
                mock_cls.return_value = mock_client

                result = await engine._check_tls_host("webmail.example.com", 5.0)

        assert result is None

    @pytest.mark.asyncio
    async def test_check_tls_host_ssl_error_returns_message(self):
        """When an SSL certificate error occurs, _check_tls_host must return the error string."""
        engine = _make_wm_engine()

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_err = httpx.ConnectError("SSL handshake failed")
        connect_err.__context__ = ssl_exc

        with patch.object(engine._ssrf_guard, "validate_domain_for_scan", new_callable=AsyncMock):
            with patch("httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.head = AsyncMock(side_effect=connect_err)
                mock_cls.return_value = mock_client

                result = await engine._check_tls_host("bad-cert.example.com", 5.0)

        assert result is not None
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_check_tls_host_ssrf_blocked_returns_none(self):
        """SSRF-blocked host must return None (not emit TLS finding)."""
        engine = _make_wm_engine()

        with patch.object(
            engine._ssrf_guard,
            "validate_domain_for_scan",
            side_effect=SSRFGuardError("private"),
        ):
            result = await engine._check_tls_host("169.254.169.254", 5.0)

        assert result is None

    def test_emit_tls_finding_produces_finding(self):
        """_emit_tls_finding must produce a HIGH-severity WM-TLS-CERT finding."""
        engine = _make_wm_engine()
        result = EngineResult(engine="webmail", domain="example.com")

        engine._emit_tls_finding(result, "webmail.example.com", "certificate verify failed")

        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.check_id == "WM-TLS-CERT"
        assert f.risk_level == RiskLevel.HIGH
        assert "webmail.example.com" in f.title

    @pytest.mark.asyncio
    async def test_run_emits_tls_finding_when_cert_invalid(self):
        """_run must emit WM-TLS-CERT when _check_tls_host returns an error."""
        engine = _make_wm_engine()

        with patch.object(engine, "_check_tls_host", AsyncMock(return_value="certificate verify failed")):
            with patch.object(engine._ssrf_guard, "validate_domain_for_scan", new_callable=AsyncMock):
                with patch("httpx.AsyncClient") as mock_cls:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=False)
                    mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
                    mock_cls.return_value = mock_client

                    result = await engine._run("example.com")

        tls_findings = [f for f in result.findings if f.check_id == "WM-TLS-CERT"]
        assert len(tls_findings) > 0


# ── Cookie Security Findings ───────────────────────────────────────────────────


class TestCookieSecurityFindings:
    def test_missing_secure_flag(self):
        engine = _make_wm_engine()
        result = EngineResult(engine="webmail", domain="example.com")
        ep = _make_endpoint(headers={"set-cookie": "session=abc123; Path=/; HttpOnly; SameSite=Strict"})
        engine._emit_cookie_findings(result, ep)

        check_ids = [f.check_id for f in result.findings]
        assert "WM-COOKIE-SECURE" in check_ids
        assert "WM-COOKIE-HTTPONLY" not in check_ids
        assert "WM-COOKIE-SAMESITE" not in check_ids

    def test_missing_httponly_flag(self):
        engine = _make_wm_engine()
        result = EngineResult(engine="webmail", domain="example.com")
        ep = _make_endpoint(headers={"set-cookie": "session=abc123; Path=/; Secure; SameSite=Strict"})
        engine._emit_cookie_findings(result, ep)

        check_ids = [f.check_id for f in result.findings]
        assert "WM-COOKIE-HTTPONLY" in check_ids
        assert "WM-COOKIE-SECURE" not in check_ids

    def test_missing_samesite_attribute(self):
        engine = _make_wm_engine()
        result = EngineResult(engine="webmail", domain="example.com")
        ep = _make_endpoint(headers={"set-cookie": "session=abc123; Path=/; Secure; HttpOnly"})
        engine._emit_cookie_findings(result, ep)

        check_ids = [f.check_id for f in result.findings]
        assert "WM-COOKIE-SAMESITE" in check_ids
        assert "WM-COOKIE-SECURE" not in check_ids
        assert "WM-COOKIE-HTTPONLY" not in check_ids

    def test_insecure_cookie_all_flags_missing(self):
        engine = _make_wm_engine()
        result = EngineResult(engine="webmail", domain="example.com")
        ep = _make_endpoint(headers={"set-cookie": "session=abc123; Path=/"})
        engine._emit_cookie_findings(result, ep)

        check_ids = [f.check_id for f in result.findings]
        assert "WM-COOKIE-SECURE" in check_ids
        assert "WM-COOKIE-HTTPONLY" in check_ids
        assert "WM-COOKIE-SAMESITE" in check_ids

    def test_fully_secure_cookie_no_findings(self):
        engine = _make_wm_engine()
        result = EngineResult(engine="webmail", domain="example.com")
        ep = _make_endpoint(
            headers={"set-cookie": "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"}
        )
        engine._emit_cookie_findings(result, ep)
        assert len(result.findings) == 0

    def test_no_set_cookie_no_findings(self):
        engine = _make_wm_engine()
        result = EngineResult(engine="webmail", domain="example.com")
        ep = _make_endpoint(headers={})
        engine._emit_cookie_findings(result, ep)
        assert len(result.findings) == 0

    def test_cookie_findings_severity_by_class(self):
        """
        Phase 4.2: cookie severity calibrated by class.
        'token' matches session/auth class → Secure/HttpOnly = HIGH, SameSite = MEDIUM.
        'preferences' (unknown) → all MEDIUM.
        """
        engine = _make_wm_engine()

        # session/auth cookie: Secure+HttpOnly missing → HIGH
        result_sess = EngineResult(engine="webmail", domain="example.com")
        ep_sess = _make_endpoint(headers={"set-cookie": "token=xyz; Path=/"})
        engine._emit_cookie_findings(result_sess, ep_sess)
        secure_f = next((f for f in result_sess.findings if f.check_id == "WM-COOKIE-SECURE"), None)
        assert secure_f is not None
        assert secure_f.risk_level == RiskLevel.HIGH

        # unknown cookie: Secure missing → MEDIUM
        result_unk = EngineResult(engine="webmail", domain="example.com")
        ep_unk = _make_endpoint(headers={"set-cookie": "preferences=dark; Path=/"})
        engine._emit_cookie_findings(result_unk, ep_unk)
        secure_u = next((f for f in result_unk.findings if f.check_id == "WM-COOKIE-SECURE"), None)
        assert secure_u is not None
        assert secure_u.risk_level == RiskLevel.MEDIUM


# ── Zimbra 4-Component Version Parsing ────────────────────────────────────────


class TestZimbraVersionParsing:
    def test_parse_zimbra_patch_notation(self):
        """'8.8.15 Patch 41' must parse to (8, 8, 15, 41)."""
        engine = _make_vi_engine()
        assert engine._parse_semver("8.8.15 Patch 41") == (8, 8, 15, 41)

    def test_parse_zimbra_patch_uppercase(self):
        engine = _make_vi_engine()
        assert engine._parse_semver("9.0.0 Patch 34") == (9, 0, 0, 34)

    def test_parse_zimbra_p_notation(self):
        """'8.8.15.p41' must parse to (8, 8, 15, 41)."""
        engine = _make_vi_engine()
        assert engine._parse_semver("8.8.15.p41") == (8, 8, 15, 41)

    def test_zimbra_unpatched_base_is_vulnerable(self):
        """
        Zimbra 8.8.15 (no patch) must be CONFIRMED vulnerable for CVE-2023-37580
        since it is < '8.8.15 Patch 41' (= 8.8.15.41 = (8,8,15,41)).
        Before the fix, this was NOT_AFFECTED because '< 8.8.15 Patch 41' was
        parsed as '< 8.8.15', and (8,8,15,0) < (8,8,15,0) = False.
        """
        engine = _make_vi_engine()
        result = engine._check_version_range(
            "8.8.15",   # unpatched base → (8,8,15,0)
            [">=8.8.0, < 8.8.15.41"],
            ["8.8.15.41"],
        )
        assert result == CVEConfidence.CONFIRMED

    def test_zimbra_patched_patch_41_is_not_affected(self):
        """8.8.15 Patch 41 must be NOT_AFFECTED for CVE-2023-37580."""
        engine = _make_vi_engine()
        result = engine._check_version_range(
            "8.8.15 Patch 41",   # = (8,8,15,41)
            [">=8.8.0, < 8.8.15.41"],
            ["8.8.15.41"],
        )
        assert result == CVEConfidence.NOT_AFFECTED

    def test_zimbra_patch_40_is_still_vulnerable(self):
        """8.8.15 Patch 40 must be CONFIRMED (patch 40 < patch 41 = still vulnerable)."""
        engine = _make_vi_engine()
        # Using 4-component numeric since the patched version in DB is "8.8.15.41"
        result = engine._check_version_range(
            "8.8.15.40",  # = (8,8,15,40)
            [">=8.8.0, < 8.8.15.41"],
            ["8.8.15.41"],
        )
        assert result == CVEConfidence.CONFIRMED

    @pytest.mark.asyncio
    async def test_zimbra_cve_2023_37580_unpatched_base(self):
        """Full pipeline: Zimbra 8.8.15 (unpatched) must trigger CVE-2023-37580."""
        engine = _make_vi_engine()
        f = _make_webmail_finding("Zimbra", "8.8.15")
        result = await engine.run_from_findings("example.com", [f])
        cve_ids = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if ev.technical_details and "cve_id" in ev.technical_details
        ]
        assert "CVE-2023-37580" in cve_ids

    @pytest.mark.asyncio
    async def test_zimbra_10_0_8_critical(self):
        """Zimbra 10.0.8 must trigger CVE-2024-45519 at CRITICAL severity."""
        engine = _make_vi_engine()
        f = _make_webmail_finding("Zimbra", "10.0.8")
        result = await engine.run_from_findings("example.com", [f])
        risk_levels = [fi.risk_level for fi in result.findings]
        assert RiskLevel.CRITICAL in risk_levels


# ── Exchange OWA Build Number CVE Matching ─────────────────────────────────────


class TestExchangeOWAVersionMatching:
    def test_parse_exchange_owa_build_number(self):
        """OWA version '15.1.2375.17' must parse to (15, 1, 2375, 17)."""
        engine = _make_vi_engine()
        assert engine._parse_semver("15.1.2375.17") == (15, 1, 2375, 17)

    def test_exchange_2016_cu19_unpatched_proxylogon(self):
        """
        Exchange 2016 CU19 unpatched (15.1.2176.1) must be CONFIRMED for CVE-2021-26855.
        Before fix, affected_versions = ["Exchange Server 2016 CU18/CU19"] — unparseable.
        """
        engine = _make_vi_engine()
        result = engine._check_version_range(
            "15.1.2176.1",    # CU19 unpatched → (15,1,2176,1)
            [">=15.1.2176.0, < 15.1.2176.14"],
            ["15.0.1497.26", "15.1.2106.13", "15.1.2176.14", "15.2.792.13"],
        )
        assert result == CVEConfidence.CONFIRMED

    def test_exchange_2016_cu19_patched_not_affected(self):
        """Exchange 2016 CU19 patched (15.1.2176.14) must be NOT_AFFECTED."""
        engine = _make_vi_engine()
        result = engine._check_version_range(
            "15.1.2176.14",   # CU19 patched
            [">=15.1.2176.0, < 15.1.2176.14"],
            ["15.0.1497.26", "15.1.2106.13", "15.1.2176.14", "15.2.792.13"],
        )
        assert result == CVEConfidence.NOT_AFFECTED

    def test_exchange_2016_cu21_not_affected_proxylogon(self):
        """
        Exchange 2016 CU21 (15.1.2375.17) was released after March 2021 patch
        and must be NOT_AFFECTED for CVE-2021-26855.
        """
        engine = _make_vi_engine()
        result = engine._check_version_range(
            "15.1.2375.17",   # CU21, post-patch → (15,1,2375,17)
            [
                ">=15.0.1000.0, < 15.0.1497.26",
                ">=15.1.0, < 15.1.2106.13",
                ">=15.1.2176.0, < 15.1.2176.14",
                ">=15.2.0, < 15.2.792.13",
            ],
            ["15.0.1497.26", "15.1.2106.13", "15.1.2176.14", "15.2.792.13"],
        )
        assert result == CVEConfidence.NOT_AFFECTED

    @pytest.mark.asyncio
    async def test_owa_cu19_unpatched_triggers_proxylogon(self):
        """Full pipeline: OWA version 15.1.2176.1 must emit CVE-2021-26855 finding."""
        engine = _make_vi_engine()
        f = _make_webmail_finding("Microsoft OWA", "15.1.2176.1")
        result = await engine.run_from_findings("example.com", [f])
        cve_ids = [
            ev.technical_details["cve_id"]
            for finding in result.findings
            for ev in finding.evidence
            if ev.technical_details and "cve_id" in ev.technical_details
        ]
        assert "CVE-2021-26855" in cve_ids


# ── _aggregate_confidence / per-CVE tracking fix ──────────────────────────────


class TestAggregateConfidenceFix:
    @pytest.mark.asyncio
    async def test_confirmed_version_in_range_gives_confirmed(self):
        """When version falls in an affected range, match.confidence must be CONFIRMED."""
        engine = _make_vi_engine()
        f = _make_webmail_finding("Roundcube", "1.6.2")  # < 1.6.3 → CONFIRMED
        result = await engine.run_from_findings("example.com", [f])

        vi_findings = [
            fi for fi in result.findings
            if fi.check_id.startswith("VI-")
        ]
        # Confidence for a CONFIRMED match = 0.9
        for fi in vi_findings:
            if fi.check_id == "VI-CVE-2023-43770":
                assert fi.confidence >= 0.8

    @pytest.mark.asyncio
    async def test_no_version_gives_potentially_not_confirmed(self):
        """
        When no version is known, match.confidence must be POTENTIALLY (not CONFIRMED).
        Before fix, _aggregate_confidence returned CONFIRMED whenever version was truthy.
        """
        engine = _make_vi_engine()
        f = _make_webmail_finding("Roundcube", None)  # no version
        result = await engine.run_from_findings("example.com", [f])

        vi_findings = [fi for fi in result.findings if fi.check_id.startswith("VI-")]
        for fi in vi_findings:
            # POTENTIALLY maps to 0.5 confidence score, CONFIRMED maps to 0.9
            assert fi.confidence <= 0.6, (
                f"Expected <=0.6 (POTENTIALLY) for version-unknown finding, got {fi.confidence}"
            )

    @pytest.mark.asyncio
    async def test_fully_patched_roundcube_emits_no_findings(self):
        """Roundcube 1.6.8 is past all patched versions — zero CVE findings expected."""
        engine = _make_vi_engine()
        f = _make_webmail_finding("Roundcube", "1.6.8")
        result = await engine.run_from_findings("example.com", [f])
        # Updated: the engine deliberately emits one INFO "VI-CLEAN-<PRODUCT>"
        # summary (consumed by frontend VulnIntel.tsx) when every checked CVE is
        # NOT_AFFECTED. The contract is "no CVE findings", not "no findings".
        cve_findings = [fi for fi in result.findings if fi.check_id.startswith("VI-CVE-")]
        assert cve_findings == [], (
            f"Expected 0 CVE findings for patched Roundcube 1.6.8, got {len(cve_findings)}"
        )
        assert all(
            fi.check_id == "VI-CLEAN-ROUNDCUBE" and fi.risk_level == RiskLevel.INFO
            for fi in result.findings
        )
