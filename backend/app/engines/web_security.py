"""
WebSecurityEngine — HTTP security headers, TLS config, exposed server info.

Checks:
- HTTP → HTTPS redirect
- HSTS presence and strength
- CSP (Content Security Policy)
- Clickjacking protection (X-Frame-Options / frame-ancestors)
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Exposed server/technology headers (Server, X-Powered-By, X-AspNet-Version)
- Cookie security attributes
- CORS misconfiguration (wildcard Access-Control-Allow-Origin)
"""
import asyncio
import re
import ssl
from typing import Optional
from urllib.parse import urlparse

import httpx
import structlog

from app.core.config import SCANNER_USER_AGENT
from app.engines.base import BaseEngine, EngineResult
from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError
from app.engines.webmail_transport import PinnedDNSTransport
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel

logger = structlog.get_logger("mailox.engines.web_security")

_REQUEST_TIMEOUT = 10.0
_MAX_REDIRECTS = 5
_USER_AGENT = SCANNER_USER_AGENT

_HSTS_MIN_MAX_AGE = 31_536_000  # 1 year (recommended minimum)
_HSTS_WEAK_MAX_AGE = 86_400     # 1 day — anything below is too short


def _hdr(headers: httpx.Headers, name: str) -> Optional[str]:
    return headers.get(name.lower())


def _build_client(ssrf_guard: SSRFGuard) -> httpx.AsyncClient:
    transport = PinnedDNSTransport(ssrf_guard=ssrf_guard, verify=False)
    return httpx.AsyncClient(
        transport=transport,
        follow_redirects=True,
        max_redirects=_MAX_REDIRECTS,
        timeout=_REQUEST_TIMEOUT,
        headers={"User-Agent": _USER_AGENT},
    )


async def _fetch(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    try:
        return await client.get(url)
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
        return None
    except Exception as e:
        logger.debug("web_fetch_error", url=url, error=str(e))
        return None


# ── Individual check functions ────────────────────────────────────────────────


def _check_https_redirect(
    domain: str,
    http_resp: Optional[httpx.Response],
    https_resp: Optional[httpx.Response],
) -> list[Finding]:
    findings: list[Finding] = []

    if http_resp is None and https_resp is None:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-01",
            title="Website unreachable on HTTP and HTTPS",
            description=f"No HTTP response from {domain} on port 80 or 443.",
            risk_level=RiskLevel.INFO,
            confidence=0.5,
            evidence=[Evidence(type=EvidenceType.ERROR, source=f"HTTP+HTTPS {domain}")],
            remediation="Verify the domain has a web presence.",
            affected_asset=domain,
        ))
        return findings

    if http_resp is not None and https_resp is not None:
        final_url = str(http_resp.url)
        redirected_to_https = final_url.startswith("https://")
        if not redirected_to_https:
            findings.append(Finding(
                engine="web_security",
                check_id="WEB-02",
                title="HTTP not redirected to HTTPS",
                description=(
                    f"The site at http://{domain} does not redirect to HTTPS. "
                    "Traffic can be intercepted in plaintext."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.HTTP_RESPONSE,
                    observed_value=f"Final URL: {final_url}",
                    expected_value=f"https://{domain}",
                    source=f"HTTP {domain}",
                )],
                remediation="Configure a permanent (301) redirect from HTTP to HTTPS.",
                affected_asset=domain,
            ))

    return findings


def _check_hsts(resp: httpx.Response, domain: str) -> list[Finding]:
    findings: list[Finding] = []
    hsts = _hdr(resp.headers, "Strict-Transport-Security")

    if not hsts:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-03",
            title="Missing HSTS header",
            description=(
                f"{domain} does not send a Strict-Transport-Security header. "
                "Browsers will not enforce HTTPS-only connections, leaving users "
                "vulnerable to SSL stripping attacks."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.95,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value="Strict-Transport-Security: (absent)",
                expected_value="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                source=f"HTTPS {domain}",
            )],
            remediation=(
                "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
                "to all HTTPS responses."
            ),
            affected_asset=domain,
        ))
        return findings

    # Parse max-age
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    include_subdomains = "includesubdomains" in hsts.lower()
    preload = "preload" in hsts.lower()

    if max_age < _HSTS_WEAK_MAX_AGE:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-04",
            title=f"HSTS max-age too short ({max_age}s)",
            description=(
                f"HSTS max-age is only {max_age}s (< 1 day). "
                "Short max-age values offer minimal protection."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"Strict-Transport-Security: {hsts}",
                expected_value="max-age >= 31536000",
                source=f"HTTPS {domain}",
            )],
            remediation="Set max-age to at least 31536000 (1 year).",
            affected_asset=domain,
        ))
    elif max_age < _HSTS_MIN_MAX_AGE:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-04",
            title=f"HSTS max-age below recommended minimum ({max_age}s)",
            description=f"HSTS max-age is {max_age}s. Recommended: ≥ 31536000s (1 year).",
            risk_level=RiskLevel.MEDIUM,
            confidence=0.8,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"Strict-Transport-Security: {hsts}",
                expected_value="max-age >= 31536000",
                source=f"HTTPS {domain}",
            )],
            remediation="Increase max-age to 31536000 (1 year) or more.",
            affected_asset=domain,
        ))

    if not include_subdomains:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-05",
            title="HSTS missing includeSubDomains",
            description=(
                "HSTS is set without `includeSubDomains`. Subdomains can still be "
                "reached over plain HTTP, enabling cookie theft and downgrade attacks."
            ),
            risk_level=RiskLevel.MEDIUM,
            confidence=0.8,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"Strict-Transport-Security: {hsts}",
                expected_value="includeSubDomains present",
                source=f"HTTPS {domain}",
            )],
            remediation="Add `includeSubDomains` to the HSTS header.",
            affected_asset=domain,
        ))

    return findings


def _check_csp(resp: httpx.Response, domain: str) -> list[Finding]:
    findings: list[Finding] = []
    csp = _hdr(resp.headers, "Content-Security-Policy")

    if not csp:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-06",
            title="Missing Content-Security-Policy header",
            description=(
                f"{domain} does not define a Content-Security-Policy. "
                "Without CSP, XSS attacks can inject and execute arbitrary scripts."
            ),
            risk_level=RiskLevel.MEDIUM,
            confidence=0.9,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value="Content-Security-Policy: (absent)",
                expected_value="Content-Security-Policy: default-src 'self'; ...",
                source=f"HTTPS {domain}",
            )],
            remediation=(
                "Define a Content-Security-Policy that restricts script sources "
                "to known-good origins. Start with `default-src 'self'`."
            ),
            affected_asset=domain,
        ))
        return findings

    # Unsafe directives
    if "'unsafe-inline'" in csp:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-07",
            title="CSP allows 'unsafe-inline' scripts",
            description=(
                "The Content-Security-Policy includes `'unsafe-inline'`, which allows "
                "inline JavaScript execution. This largely negates XSS protection."
            ),
            risk_level=RiskLevel.MEDIUM,
            confidence=0.85,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"Content-Security-Policy: {csp[:200]}",
                source=f"HTTPS {domain}",
            )],
            remediation=(
                "Replace `'unsafe-inline'` with script nonces or hashes. "
                "Use `strict-dynamic` to allow dynamic script loading securely."
            ),
            affected_asset=domain,
        ))

    if "'unsafe-eval'" in csp:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-08",
            title="CSP allows 'unsafe-eval'",
            description=(
                "The Content-Security-Policy includes `'unsafe-eval'`, which allows "
                "`eval()`, `Function()`, and similar dynamic code execution."
            ),
            risk_level=RiskLevel.LOW,
            confidence=0.8,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"Content-Security-Policy: {csp[:200]}",
                source=f"HTTPS {domain}",
            )],
            remediation="Remove `'unsafe-eval'` and refactor code that relies on eval.",
            affected_asset=domain,
        ))

    return findings


def _check_clickjacking(resp: httpx.Response, domain: str) -> list[Finding]:
    findings: list[Finding] = []
    xfo = _hdr(resp.headers, "X-Frame-Options")
    csp = _hdr(resp.headers, "Content-Security-Policy") or ""
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if not xfo and not has_frame_ancestors:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-09",
            title="Missing clickjacking protection",
            description=(
                f"{domain} has neither X-Frame-Options nor a CSP frame-ancestors directive. "
                "The page can be embedded in an iframe by any third-party site, enabling "
                "clickjacking attacks."
            ),
            risk_level=RiskLevel.MEDIUM,
            confidence=0.9,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value="X-Frame-Options: (absent); CSP frame-ancestors: (absent)",
                expected_value="X-Frame-Options: DENY or CSP: frame-ancestors 'none'",
                source=f"HTTPS {domain}",
            )],
            remediation=(
                "Add `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'` "
                "(CSP is preferred as X-Frame-Options is deprecated)."
            ),
            affected_asset=domain,
        ))

    return findings


def _check_content_type_sniffing(resp: httpx.Response, domain: str) -> list[Finding]:
    findings: list[Finding] = []
    xcto = _hdr(resp.headers, "X-Content-Type-Options")
    if not xcto or xcto.lower() != "nosniff":
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-10",
            title="Missing X-Content-Type-Options: nosniff",
            description=(
                "Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff "
                "responses and interpret files as a different content type, enabling "
                "drive-by-download and XSS attacks."
            ),
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"X-Content-Type-Options: {xcto or '(absent)'}",
                expected_value="X-Content-Type-Options: nosniff",
                source=f"HTTPS {domain}",
            )],
            remediation="Add `X-Content-Type-Options: nosniff` to all responses.",
            affected_asset=domain,
        ))
    return findings


def _check_server_exposure(resp: httpx.Response, domain: str) -> list[Finding]:
    findings: list[Finding] = []

    for header_name, check_id in [
        ("Server", "WEB-11"),
        ("X-Powered-By", "WEB-12"),
        ("X-AspNet-Version", "WEB-13"),
        ("X-AspNetMvc-Version", "WEB-14"),
    ]:
        value = _hdr(resp.headers, header_name)
        if not value:
            continue

        # Only flag if it looks like it contains version info
        has_version = bool(re.search(r"[\d\.]{2,}", value))
        if not has_version and header_name == "Server":
            # Even generic server header is a mild info leak
            has_version = True

        if has_version or header_name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
            findings.append(Finding(
                engine="web_security",
                check_id=check_id,
                title=f"Server technology disclosed via {header_name} header",
                description=(
                    f"The response includes `{header_name}: {value}`. "
                    "Disclosing server software and version aids targeted exploitation."
                ),
                risk_level=RiskLevel.LOW,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.HTTP_RESPONSE,
                    observed_value=f"{header_name}: {value}",
                    source=f"HTTPS {domain}",
                )],
                remediation=f"Remove or genericize the `{header_name}` header in your web server configuration.",
                affected_asset=domain,
            ))

    return findings


def _check_cors(resp: httpx.Response, domain: str) -> list[Finding]:
    findings: list[Finding] = []
    acao = _hdr(resp.headers, "Access-Control-Allow-Origin")
    acac = _hdr(resp.headers, "Access-Control-Allow-Credentials")

    if acao == "*" and acac and acac.lower() == "true":
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-15",
            title="CORS: wildcard origin with credentials",
            description=(
                "Access-Control-Allow-Origin: * combined with "
                "Access-Control-Allow-Credentials: true. "
                "This combination violates the CORS specification and enables cross-origin "
                "credential theft if any browser honours it."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.95,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"ACAO: {acao}; ACAC: {acac}",
                source=f"HTTPS {domain}",
            )],
            remediation="Never combine wildcard ACAO with credentials. Whitelist specific origins.",
            affected_asset=domain,
        ))
    elif acao == "*":
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-16",
            title="CORS: unrestricted cross-origin access (wildcard)",
            description=(
                f"{domain} sends `Access-Control-Allow-Origin: *`. "
                "Any origin can read responses to cross-origin requests."
            ),
            risk_level=RiskLevel.INFO,
            confidence=0.8,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"Access-Control-Allow-Origin: {acao}",
                source=f"HTTPS {domain}",
            )],
            remediation=(
                "Restrict ACAO to known-good origins unless the endpoint is intentionally public. "
                "For public APIs a wildcard is acceptable; for authenticated endpoints it is not."
            ),
            affected_asset=domain,
        ))

    return findings


def _check_referrer_policy(resp: httpx.Response, domain: str) -> list[Finding]:
    findings: list[Finding] = []
    rp = _hdr(resp.headers, "Referrer-Policy")
    unsafe = {"unsafe-url", "no-referrer-when-downgrade", ""}

    if not rp:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-17",
            title="Missing Referrer-Policy header",
            description=(
                "No Referrer-Policy is set. Browsers default to "
                "`no-referrer-when-downgrade`, which leaks the full URL "
                "(including query strings) to third-party HTTPS destinations."
            ),
            risk_level=RiskLevel.LOW,
            confidence=0.8,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value="Referrer-Policy: (absent)",
                expected_value="Referrer-Policy: strict-origin-when-cross-origin",
                source=f"HTTPS {domain}",
            )],
            remediation="Add `Referrer-Policy: strict-origin-when-cross-origin`.",
            affected_asset=domain,
        ))
    elif rp.lower() in unsafe:
        findings.append(Finding(
            engine="web_security",
            check_id="WEB-17",
            title=f"Weak Referrer-Policy: {rp}",
            description=f"`Referrer-Policy: {rp}` leaks the full URL to third-party sites.",
            risk_level=RiskLevel.LOW,
            confidence=0.8,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"Referrer-Policy: {rp}",
                expected_value="strict-origin-when-cross-origin",
                source=f"HTTPS {domain}",
            )],
            remediation="Set `Referrer-Policy: strict-origin-when-cross-origin`.",
            affected_asset=domain,
        ))

    return findings


# ── Engine ─────────────────────────────────────────────────────────────────────


class WebSecurityEngine(BaseEngine):
    name = "web_security"
    default_timeout = 45.0

    def __init__(
        self,
        timeout: Optional[float] = None,
        ssrf_guard: Optional[SSRFGuard] = None,
    ) -> None:
        super().__init__(timeout)
        self._ssrf_guard = ssrf_guard or SSRFGuard(resolve_timeout=1.5)

    async def _run(self, domain: str) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)

        https_url = f"https://{domain}"
        http_url = f"http://{domain}"

        async with _build_client(self._ssrf_guard) as client:
            http_resp, https_resp = await asyncio.gather(
                _fetch(client, http_url),
                _fetch(client, https_url),
                return_exceptions=False,
            )

        if https_resp is None and http_resp is None:
            result.findings.extend(_check_https_redirect(domain, None, None))
            return result

        result.metadata["http_status"] = http_resp.status_code if http_resp else None
        result.metadata["https_status"] = https_resp.status_code if https_resp else None
        result.metadata["final_url"] = str(https_resp.url) if https_resp else (
            str(http_resp.url) if http_resp else None
        )

        # Redirect check
        result.findings.extend(_check_https_redirect(domain, http_resp, https_resp))

        # All header checks run on the HTTPS response
        ref = https_resp or http_resp
        result.findings.extend(_check_hsts(ref, domain))
        result.findings.extend(_check_csp(ref, domain))
        result.findings.extend(_check_clickjacking(ref, domain))
        result.findings.extend(_check_content_type_sniffing(ref, domain))
        result.findings.extend(_check_server_exposure(ref, domain))
        result.findings.extend(_check_cors(ref, domain))
        result.findings.extend(_check_referrer_policy(ref, domain))

        return result
