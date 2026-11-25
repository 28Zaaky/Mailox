"""
Regression tests for passive-engine correctness fixes:
  - vuln_intel: per-branch version ranges, no CVE findings without a version
  - secrets: one failing/empty source never aborts the others, honest UA
  - risk_correlation: INFO / *-CLEAN ignored, exact/prefix matching, dedupe
  - dns_auth: MTA-STS policy fetched with cert validation via pinned transport
No real network: every HTTP call goes through httpx.MockTransport, DNS is mocked.
"""
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import httpx
import pytest

from app.engines.dns_auth import _check_mta_sts, _mta_sts_transport
from app.engines.risk_correlation import RiskCorrelationEngine
from app.engines.secrets import SecretsEngine
from app.engines.vuln_intel import _LOCAL_CVE_DB, CVEConfidence, VulnIntelEngine
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel


# ── helpers ────────────────────────────────────────────────────────────────────


def _smtp_banner_finding(banner: str) -> Finding:
    return Finding(
        engine="smtp_discovery",
        check_id="SMTP-00",
        title="SMTP banner",
        description="banner",
        risk_level=RiskLevel.INFO,
        confidence=0.9,
        evidence=[Evidence(
            type=EvidenceType.SMTP_RESPONSE,
            observed_value=banner,
            source="mx.example.com:25",
            technical_details={"smtp_banner": banner},
        )],
        remediation="",
        affected_asset="mx.example.com",
    )


def _webmail_finding(product: str, version):
    return Finding(
        engine="webmail",
        check_id="WM-001",
        title=f"Webmail: {product}",
        description="x",
        risk_level=RiskLevel.INFO,
        confidence=0.9,
        evidence=[Evidence(
            type=EvidenceType.HTTP_RESPONSE,
            observed_value="HTTP 200",
            source="https://webmail.example.com/",
            technical_details={"product": product, "version": version, "source_engine": "webmail"},
        )],
        remediation="",
        affected_asset="webmail.example.com",
    )


def _f(check_id, risk, confidence=0.9, asset="example.com"):
    return Finding(
        engine="test",
        check_id=check_id,
        title=check_id,
        description="d",
        risk_level=risk,
        confidence=confidence,
        evidence=[Evidence(type=EvidenceType.ANALYSIS, observed_value="x", source="https://example.com/")],
        remediation="r",
        affected_asset=asset,
    )


def _postfix_smuggling():
    return next(e for e in _LOCAL_CVE_DB["postfix"] if e["cve_id"] == "CVE-2023-51764")


def _vi_engine():
    eng = VulnIntelEngine(timeout=10.0)
    eng._redis = None
    eng._get_redis = AsyncMock(return_value=None)
    return eng


# ── vuln_intel ─────────────────────────────────────────────────────────────────


class TestVulnIntelRanges:
    @pytest.mark.parametrize("version,expected", [
        ("3.7.10", CVEConfidence.NOT_AFFECTED),   # fixed in 3.7.9 — was CONFIRMED
        ("3.7.9", CVEConfidence.NOT_AFFECTED),
        ("3.7.8", CVEConfidence.CONFIRMED),
        ("3.6.14", CVEConfidence.NOT_AFFECTED),
        ("3.6.12", CVEConfidence.CONFIRMED),
        ("3.8.3", CVEConfidence.CONFIRMED),
        ("3.8.4", CVEConfidence.NOT_AFFECTED),
        ("3.4.14", CVEConfidence.CONFIRMED),      # older than every fixed branch
        ("3.9.0", CVEConfidence.NOT_AFFECTED),
    ])
    def test_postfix_smuggling_per_branch(self, version, expected):
        e = _postfix_smuggling()
        got = _vi_engine()._check_version_range(version, e["affected_versions"], e["patched_versions"])
        assert got == expected

    def test_legacy_ored_ranges_are_normalised(self):
        """DB rows seeded with the old flat list must not swallow later branches."""
        legacy = ["< 3.8.4", "< 3.7.9", "< 3.6.13", "< 3.5.23"]
        eng = _vi_engine()
        assert eng._check_version_range("3.7.10", legacy, []) == CVEConfidence.NOT_AFFECTED
        assert eng._check_version_range("3.7.8", legacy, []) == CVEConfidence.CONFIRMED
        assert eng._check_version_range("3.5.22", legacy, []) == CVEConfidence.CONFIRMED

    def test_no_entry_in_local_db_uses_bare_ored_upper_bounds(self):
        for product, entries in _LOCAL_CVE_DB.items():
            for e in entries:
                bare = [r for r in e["affected_versions"] if "," not in r and r.strip().startswith("<")]
                assert len(bare) <= 1, f"{product} {e['cve_id']} has OR'ed bare bounds: {bare}"

    def test_postfix_db_has_no_dovecot_cve(self):
        assert "CVE-2021-33515" not in {e["cve_id"] for e in _LOCAL_CVE_DB["postfix"]}

    def test_openssl_letter_releases(self):
        eng = _vi_engine()
        e = next(x for x in _LOCAL_CVE_DB["openssl"] if x["cve_id"] == "CVE-2022-0778")
        assert eng._check_version_range("1.1.1m", e["affected_versions"], e["patched_versions"]) == CVEConfidence.CONFIRMED
        assert eng._check_version_range("1.1.1n", e["affected_versions"], e["patched_versions"]) == CVEConfidence.NOT_AFFECTED
        assert eng._check_version_range("1.0.2zc", e["affected_versions"], e["patched_versions"]) == CVEConfidence.CONFIRMED

    def test_version_below_introduced_is_not_affected(self):
        # CVE-2020-24386: >=2.3.7, <2.3.13 — 2.2.36 predates the bug
        assert _vi_engine()._check_version_range("2.2.36", [">=2.3.7, < 2.3.13"], ["2.3.13"]) == CVEConfidence.NOT_AFFECTED

    def test_no_range_data_is_uncertain(self):
        assert _vi_engine()._check_version_range("1.0.0", [], []) == CVEConfidence.UNCERTAIN


class TestVulnIntelPipeline:
    @pytest.mark.asyncio
    async def test_postfix_3710_banner_not_confirmed(self):
        eng = _vi_engine()
        res = await eng.run_from_findings("example.com", [_smtp_banner_finding("220 mx.example.com ESMTP Postfix 3.7.10")])
        confirmed = [
            f for f in res.findings
            if f.check_id == "VI-CVE-2023-51764"
            and f.evidence[0].technical_details.get("confidence") == "confirmed"
        ]
        assert confirmed == []
        assert not [f for f in res.findings if f.check_id.startswith("VI-CVE-")]

    @pytest.mark.asyncio
    async def test_postfix_without_version_emits_no_cve_finding(self):
        eng = _vi_engine()
        res = await eng.run_from_findings("example.com", [_smtp_banner_finding("220 mx.example.com ESMTP Postfix (Debian/GNU)")])
        assert not [f for f in res.findings if f.check_id.startswith("VI-CVE-")]
        assert len(res.findings) == 1
        info = res.findings[0]
        assert info.check_id == "VI-VERSION-UNDETERMINED-POSTFIX"
        assert info.risk_level == RiskLevel.INFO
        assert info.evidence[0].technical_details["confidence"] == "unknown"
        assert "CVE-2023-51764" in info.evidence[0].technical_details["cves_not_evaluated"]

    @pytest.mark.asyncio
    async def test_webmail_without_version_emits_single_info(self):
        eng = _vi_engine()
        res = await eng.run_from_findings("example.com", [_webmail_finding("Roundcube", None)])
        assert [f.check_id for f in res.findings] == ["VI-VERSION-UNDETERMINED-ROUNDCUBE"]

    @pytest.mark.asyncio
    async def test_per_cve_confidence_and_stored_cvss(self):
        eng = _vi_engine()
        res = await eng.run_from_findings("example.com", [_webmail_finding("Roundcube", "1.6.7")])
        ids = {f.check_id: f for f in res.findings}
        assert "VI-CVE-2024-37383" not in ids          # fixed in 1.6.7
        f = ids["VI-CVE-2024-42009"]                    # fixed in 1.6.8
        td = f.evidence[0].technical_details
        assert td["confidence"] == "confirmed"
        stored = next(e for e in _LOCAL_CVE_DB["roundcube"] if e["cve_id"] == "CVE-2024-42009")
        assert td["cvss_score"] == stored["cvss_score"]
        assert td["cvss_vector"] == stored["cvss_vector"]


# ── secrets ────────────────────────────────────────────────────────────────────


def _secrets_handler(seen: list, hibp_status=404, github_exc=False):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        host = request.url.host
        if host == "haveibeenpwned.com":
            return httpx.Response(hibp_status, json=[] if hibp_status == 200 else None)
        if host == "api.github.com":
            if github_exc:
                raise httpx.ConnectError("boom", request=request)
            return httpx.Response(200, json={
                "total_count": 1,
                "items": [{"repository": {"full_name": "acme/cfg"}, "path": ".env", "html_url": "https://github.com/acme/cfg"}],
            })
        if host == "psbdmp.ws":
            return httpx.Response(200, json={"count": 2, "data": [{"id": "abc"}, {"id": "def"}]})
        if host == "free.intelx.io":
            if request.method == "POST":
                return httpx.Response(200, json={"id": "sid"})
            return httpx.Response(200, json={"records": [{"bucket": "leaks.private"}]})
        if host == "html.duckduckgo.com":
            return httpx.Response(200, text='<a class="result__snippet">x</a>')
        return httpx.Response(599)
    return handler


class TestSecretsSources:
    @pytest.mark.asyncio
    async def test_hibp_404_still_runs_other_sources(self):
        seen: list[httpx.Request] = []
        eng = SecretsEngine(timeout=10.0)
        eng._transport = httpx.MockTransport(_secrets_handler(seen))
        eng._intelx_api_key = "test-key"
        eng._github_token = "test-token"
        with patch("app.engines.secrets.asyncio.sleep", new=AsyncMock()):
            res = await eng.run("example.com")

        assert res.error is None
        status = res.metadata["source_status"]
        assert status["hibp"] == "no_results"
        assert res.metadata["hibp_breaches"] == 0
        for src in ("github", "pastebin", "intelx", "dork"):
            assert status[src] == "ok", (src, status)
        ids = {f.check_id for f in res.findings}
        assert {"SE-GITHUB-LEAK", "SE-PASTE-LEAK", "SE-INTELX-LEAK", "SE-DORK-LEAK"} <= ids

    @pytest.mark.asyncio
    async def test_hibp_error_and_source_exception_do_not_abort_others(self):
        seen: list[httpx.Request] = []
        eng = SecretsEngine(timeout=10.0)
        eng._transport = httpx.MockTransport(_secrets_handler(seen, hibp_status=503, github_exc=True))
        eng._intelx_api_key = None
        with patch("app.engines.secrets.asyncio.sleep", new=AsyncMock()), \
             patch("app.core.config.settings.INTELX_API_KEY", None, create=True):
            res = await eng.run("example.com")

        status = res.metadata["source_status"]
        assert status["hibp"].startswith("error")
        assert status["github"].startswith("error")
        assert status["intelx"].startswith("skipped")
        assert status["pastebin"] == "ok" and status["dork"] == "ok"
        assert res.error is None   # some sources answered
        assert {"SE-PASTE-LEAK", "SE-DORK-LEAK"} <= {f.check_id for f in res.findings}

    @pytest.mark.asyncio
    async def test_dork_user_agent_is_honest(self):
        seen: list[httpx.Request] = []
        eng = SecretsEngine(timeout=10.0)
        eng._transport = httpx.MockTransport(_secrets_handler(seen))
        with patch("app.engines.secrets.asyncio.sleep", new=AsyncMock()):
            await eng.run("example.com")
        ddg = [r for r in seen if r.url.host == "html.duckduckgo.com"]
        assert ddg
        for r in seen:
            ua = r.headers.get("user-agent", "")
            assert "MAILOX" in ua
            assert "Googlebot" not in ua and "Mozilla" not in ua


# ── risk_correlation ───────────────────────────────────────────────────────────


class TestRiskCorrelationFixes:
    def test_info_and_clean_ignored_for_chains(self):
        eng = RiskCorrelationEngine()
        findings = [
            _f("VI-CVE-2024-45519", RiskLevel.CRITICAL),
            _f("AP-STARTTLS-NOTENFORCE-CLEAN", RiskLevel.LOW),   # used to match "tls-"
            _f("SMTPS-04", RiskLevel.INFO),                      # INFO relay observation
            _f("SPF-01", RiskLevel.HIGH),
            _f("VI-CLEAN-ROUNDCUBE", RiskLevel.INFO),
        ]
        res = eng.run("example.com", findings)
        rule_ids = {c.rule_id for c in res.chains}
        assert "RC-WEBMAIL-CVE-STACK" not in rule_ids
        assert "RC-PHISHING-CHAIN" not in rule_ids
        # *-CLEAN never feeds the score
        only_clean = eng.run("example.com", [_f("AP-SMTP-SMUGGLING-CLEAN", RiskLevel.HIGH)])
        assert only_clean.risk_score == 0.0

    def test_no_substring_matching(self):
        eng = RiskCorrelationEngine()
        # "SE-" must be a prefix, "secret" substring no longer counts
        res = eng.run("example.com", [
            _f("WM-SECRET-HEADER", RiskLevel.HIGH),
            _f("SMTPS-04", RiskLevel.HIGH),
        ])
        assert "RC-CRED-OPEN-RELAY" not in {c.rule_id for c in res.chains}

    def test_real_ids_still_chain(self):
        eng = RiskCorrelationEngine()
        res = eng.run("example.com", [
            _f("SMTPS-04", RiskLevel.HIGH),
            _f("DMARC-04", RiskLevel.MEDIUM),
            _f("VI-CVE-2024-45519", RiskLevel.CRITICAL),
            _f("SMTPS-05", RiskLevel.HIGH),
        ])
        rule_ids = {c.rule_id for c in res.chains}
        assert {"RC-PHISHING-CHAIN", "RC-WEBMAIL-CVE-STACK"} <= rule_ids

    def test_duplicates_do_not_inflate_score(self):
        eng = RiskCorrelationEngine()
        one = eng.run("example.com", [_f("X-1", RiskLevel.HIGH)])
        dup = eng.run("example.com", [_f("X-1", RiskLevel.HIGH) for _ in range(5)])
        assert dup.risk_score == one.risk_score
        two_assets = eng.run("example.com", [
            _f("X-1", RiskLevel.HIGH, asset="a.example.com"),
            _f("X-1", RiskLevel.HIGH, asset="b.example.com"),
        ])
        assert two_assets.risk_score > one.risk_score

    def test_duplicate_criticals_do_not_trigger_stacked_rule(self):
        eng = RiskCorrelationEngine()
        res = eng.run("example.com", [_f("CRIT-1", RiskLevel.CRITICAL) for _ in range(3)])
        assert "RC-STACKED-CRITICALS" not in {c.rule_id for c in res.chains}


# ── dns_auth MTA-STS ───────────────────────────────────────────────────────────


def _sts_resolver():
    resolver = MagicMock()

    async def _resolve(name, rdtype, **kw):
        name = str(name).rstrip(".")
        if rdtype == "TXT" and name == "_mta-sts.example.com":
            rd = MagicMock()
            rd.strings = [b"v=STSv1; id=20240101"]
            return [rd]
        raise dns.resolver.NoAnswer

    resolver.resolve = _resolve
    return resolver


class TestMtaStsPolicyFetch:
    def test_transport_is_pinned_and_verifying(self):
        from app.engines.webmail_transport import PinnedDNSTransport
        t = _mta_sts_transport()
        assert isinstance(t, PinnedDNSTransport)
        ctx = t._pool._ssl_context
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname

    @pytest.mark.asyncio
    async def test_invalid_certificate_emits_finding(self):
        def handler(request):
            cause = ssl.SSLCertVerificationError(
                1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch"
            )
            raise httpx.ConnectError("TLS failure", request=request) from cause

        with patch("app.engines.dns_auth._mta_sts_transport", return_value=httpx.MockTransport(handler)):
            findings, meta = await _check_mta_sts(_sts_resolver(), "example.com")

        assert meta["policy_reachable"] is False
        assert meta["policy_error"] == "invalid_certificate"
        f = next(x for x in findings if x.check_id == "MTAS-05")
        assert f.risk_level == RiskLevel.MEDIUM
        assert f.affected_asset == "mta-sts.example.com"

    @pytest.mark.asyncio
    async def test_valid_enforce_policy_no_finding(self):
        def handler(request):
            return httpx.Response(200, text="version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n")

        with patch("app.engines.dns_auth._mta_sts_transport", return_value=httpx.MockTransport(handler)):
            findings, meta = await _check_mta_sts(_sts_resolver(), "example.com")
        assert meta["mode"] == "enforce"
        assert not [x for x in findings if x.check_id.startswith("MTAS-")]

    @pytest.mark.asyncio
    async def test_redirect_is_not_followed(self):
        calls = []

        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(301, headers={"Location": "https://evil.example.net/policy"})

        with patch("app.engines.dns_auth._mta_sts_transport", return_value=httpx.MockTransport(handler)):
            findings, meta = await _check_mta_sts(_sts_resolver(), "example.com")
        assert len(calls) == 1
        assert any(x.check_id == "MTAS-04" for x in findings)

    @pytest.mark.asyncio
    async def test_ssrf_blocked_policy_host_no_cert_finding(self):
        from app.engines.ssrf_guard import SSRFGuardError

        def handler(request):
            raise SSRFGuardError("Target IP not allowed: private")

        with patch("app.engines.dns_auth._mta_sts_transport", return_value=httpx.MockTransport(handler)):
            findings, meta = await _check_mta_sts(_sts_resolver(), "example.com")
        assert meta["policy_error"] == "ssrf_blocked"
        assert not any(x.check_id == "MTAS-05" for x in findings)
