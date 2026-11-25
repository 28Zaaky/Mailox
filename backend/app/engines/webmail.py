"""
WebmailEngine — Module 05: Webmail & Email Web Application Security.

Discovers and assesses webmail interfaces exposed by a target domain.

Design constraints:
- All HTTP probes go through SSRFGuard IP validation, including redirect destinations
- DNS pinning via PinnedDNSTransport: validated IP is used for TCP connect;
  OS resolver never called after validation — prevents DNS rebinding
- TLS certificate errors are captured as findings (not silently ignored)
- Engines NEVER raise — errors captured in EngineResult.error
- Confidence scores reflect detection quality, not severity
- A 200 response alone is NOT sufficient to confirm a webmail presence
- Cookie security (Secure, HttpOnly, SameSite) checked on discovered endpoints
  with severity calibrated to cookie type (session/auth vs analytics vs unknown)

Security note (SSRF + DNS pinning):
  PinnedDNSTransport replaces httpcore's network backend so that EVERY TCP
  connection (including redirect hops) first calls SSRFGuard.resolve_and_validate.
  The event hook (_ssrf_redirect_hook) remains as defence-in-depth for hostname
  blocking before httpx even initiates the request.
"""
import asyncio
import re
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx
import structlog

from app.core.config import SCANNER_USER_AGENT
from app.engines.base import BaseEngine, EngineResult
from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError
from app.engines.webmail_transport import PinnedDNSTransport
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel

logger = structlog.get_logger("mailox.engines.webmail")


@dataclass
class WebmailEndpoint:
    url: str
    product: str
    version: Optional[str]
    confidence: float
    status_code: int
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    fingerprint_signals: list[str] = field(default_factory=list)


# (path, candidate_product, min_confidence_if_200)
_PROBE_PATHS: list[tuple[str, str, float]] = [
    # Roundcube
    ("/webmail", "Roundcube", 0.3),
    ("/roundcube", "Roundcube", 0.5),
    ("/roundcube/", "Roundcube", 0.5),
    # Zimbra
    ("/zimbra", "Zimbra", 0.6),
    ("/zimbra/", "Zimbra", 0.6),
    # Microsoft OWA / Exchange
    ("/owa", "Microsoft OWA", 0.6),
    ("/owa/", "Microsoft OWA", 0.6),
    ("/exchange", "Microsoft Exchange", 0.4),
    ("/EWS/Exchange.asmx", "Microsoft Exchange", 0.7),
    ("/mapi", "Microsoft Exchange", 0.7),
    ("/autodiscover/autodiscover.xml", "Microsoft Exchange", 0.6),
    # Horde
    ("/horde", "Horde", 0.5),
    ("/horde/", "Horde", 0.5),
    # SOGo
    ("/SOGo", "SOGo", 0.6),
    ("/SOGo/", "SOGo", 0.6),
    # RainLoop
    ("/rainloop", "RainLoop", 0.5),
    ("/", "Unknown", 0.1),   # root — only used if other signals confirm
]

_WEBMAIL_SUBDOMAINS = ["webmail", "mail", "owa", "zimbra", "exchange", "mx", "smtp"]

# (product, signal_type, pattern/header_name, header_value_re, body_re, weight)
# signal_type: "header" | "body" | "path"
_FINGERPRINT_RULES: list[dict] = [
    # Roundcube
    {"product": "Roundcube", "type": "body", "pattern": r'(?i)(rcmlogon|roundcube\s+webmail|/roundcube/|rcube_|RoundCube)', "weight": 0.9},
    {"product": "Roundcube", "type": "header", "name": "X-Powered-By", "pattern": r'(?i)roundcube', "weight": 0.95},
    # Zimbra
    {"product": "Zimbra", "type": "body", "pattern": r'(?i)(zimbra\s+(collaboration|webmail|admin)|/zimbra/|zm_loginpage|loginOp=logout&)', "weight": 0.9},
    {"product": "Zimbra", "type": "header", "name": "X-Zimbra-Error", "pattern": r".*", "weight": 0.95},
    {"product": "Zimbra", "type": "body", "pattern": r'(?i)Zimbra', "weight": 0.5},
    # Microsoft OWA
    {"product": "Microsoft OWA", "type": "body", "pattern": r'(?i)(Outlook\s+Web\s+App|OutlookSession|OWA\s+login|/owa/auth)', "weight": 0.9},
    {"product": "Microsoft OWA", "type": "header", "name": "X-OWA-Version", "pattern": r".*", "weight": 0.95},
    {"product": "Microsoft OWA", "type": "header", "name": "X-FEServer", "pattern": r".*", "weight": 0.8},
    {"product": "Microsoft OWA", "type": "header", "name": "X-BEServer", "pattern": r".*", "weight": 0.8},
    # Microsoft Exchange
    {"product": "Microsoft Exchange", "type": "header", "name": "X-MS-Server-Fqdn", "pattern": r".*", "weight": 0.95},
    {"product": "Microsoft Exchange", "type": "header", "name": "X-EWS-TargetMailboxServer", "pattern": r".*", "weight": 0.95},
    {"product": "Microsoft Exchange", "type": "body", "pattern": r'(?i)(Microsoft\s+Exchange\s+Server|NTLM\s+Authentication\s+Required|/autodiscover/)', "weight": 0.8},
    # Horde
    {"product": "Horde", "type": "body", "pattern": r'(?i)(Horde\s+Webmail|horde_login|imp\.login|/horde/)', "weight": 0.9},
    # SOGo
    {"product": "SOGo", "type": "body", "pattern": r'(?i)(SOGo\s+Web\s|sogo-webmail|/SOGo/|SOGoRootPage)', "weight": 0.9},
    {"product": "SOGo", "type": "header", "name": "X-SOGo-Version", "pattern": r".*", "weight": 0.95},
    # RainLoop
    {"product": "RainLoop", "type": "body", "pattern": r'(?i)(rainloop|app\.rainloop\.net)', "weight": 0.9},
    # cPanel Webmail
    {"product": "cPanel Webmail", "type": "body", "pattern": r'(?i)(cPanel\s+Webmail|webmail\.cpanel\.net)', "weight": 0.9},
    # Generic: version leak in Server header
    {"product": None, "type": "header", "name": "Server", "pattern": r"(?i)(roundcube|zimbra|horde|opensmtpd)", "weight": 0.7},
]

# Cookie name patterns for severity calibration
_SESSION_COOKIE_RE = re.compile(
    r'(?i)^(sess(ion(id)?)?|token|auth(entication)?|jwt|remember(_me)?|'
    r'credential|access_token|refresh_token|sid|user_?id|login|bearer)',
)
_ANALYTICS_COOKIE_RE = re.compile(
    r'(?i)^(_ga|_gid|_gat|_pk_|_paq|__utm[a-z]?|cookie_?consent|'
    r'_hjid|hubspot|_fbp|_fbc|intercom)',
)

# Security header checks: (header_name, check_description, severity, missing_severity)
_SECURITY_HEADERS: list[tuple[str, str, str, str]] = [
    ("Strict-Transport-Security", "HSTS", "medium", "medium"),
    ("Content-Security-Policy", "CSP", "medium", "medium"),
    ("X-Frame-Options", "X-Frame-Options", "low", "low"),
    ("X-Content-Type-Options", "X-Content-Type-Options", "low", "low"),
    ("Referrer-Policy", "Referrer-Policy", "info", "info"),
    ("Permissions-Policy", "Permissions-Policy", "info", "info"),
]

# Headers that should NOT be exposed (information disclosure)
_SENSITIVE_HEADERS = [
    "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Server-Name",
]

_RISK_MAP = {
    "critical": RiskLevel.CRITICAL,
    "high": RiskLevel.HIGH,
    "medium": RiskLevel.MEDIUM,
    "low": RiskLevel.LOW,
    "info": RiskLevel.INFO,
}


class WebmailEngine(BaseEngine):
    name: str = "webmail"
    default_timeout: float = 60.0

    def __init__(self, timeout: Optional[float] = None) -> None:
        super().__init__(timeout)
        self._ssrf_guard = SSRFGuard()

    async def _ssrf_redirect_hook(self, request: httpx.Request) -> None:
        """Pre-request hook fired for EVERY httpx request, including redirect hops.

        Validates each destination URL through SSRFGuard before the request is sent.
        This prevents an attacker-controlled webmail redirect target from bypassing
        the initial SSRF check in _probe_host (which only validates the first hop).
        """
        host = request.url.host
        if host:
            await self._ssrf_guard.validate_domain_for_scan(host)
            # SSRFGuardError propagates through httpx and is caught in _probe_url

    async def _check_tls_host(self, host: str, timeout: float) -> Optional[str]:
        """Probe host HTTPS with certificate verification enabled.

        Returns a classified error string (prefix:detail) if cert validation
        fails, None if cert is valid or error is unrelated to TLS.
        Uses PinnedDNSTransport so the TLS check targets the same IP that the
        content scan will use — not a potentially-different re-resolution.
        """
        try:
            await self._ssrf_guard.validate_domain_for_scan(host)
        except SSRFGuardError:
            return None

        tls_transport = PinnedDNSTransport(ssrf_guard=self._ssrf_guard, verify=True)
        try:
            async with httpx.AsyncClient(
                transport=tls_transport,
                follow_redirects=False,
                timeout=timeout,
            ) as tls_client:
                await tls_client.head(
                    f"https://{host}/",
                    headers={"User-Agent": SCANNER_USER_AGENT},
                )
            return None  # cert valid
        except (SSRFGuardError, httpx.ConnectError) as exc:
            if isinstance(exc, SSRFGuardError):
                return None  # SSRF-blocked host — not a TLS finding
            return self._classify_tls_error(exc)
        except Exception:
            return None

    def _classify_tls_error(self, exc: httpx.ConnectError) -> Optional[str]:
        """Return a classified error prefix:detail string, or None for non-TLS errors."""
        cause = exc.__context__
        if isinstance(cause, ssl.SSLError):
            msg = str(cause)
        else:
            msg = str(exc)
        msg_lower = msg.lower()
        if not any(kw in msg_lower for kw in ("certificate", "ssl", "tls", "handshake", "verify", "hostname", "doesn't match", "does not match", "wrong_name", "issuer", "expired")):
            return None  # non-TLS connectivity error
        if any(kw in msg_lower for kw in ("expired", "has expired", "certificate verify failed: certificate has")):
            # 'certificate has expired' appears in OpenSSL error strings
            if "expired" in msg_lower:
                return f"EXPIRED:{msg}"
        if any(kw in msg_lower for kw in ("hostname", "host name", "doesn't match", "does not match", "wrong_name", "ssl: certificate_verify_failed")):
            if any(kw in msg_lower for kw in ("hostname", "host name", "doesn't match", "does not match", "wrong_name")):
                return f"HOSTNAME_MISMATCH:{msg}"
        if any(kw in msg_lower for kw in ("self signed", "self-signed", "selfsigned", "self_signed")):
            return f"SELF_SIGNED:{msg}"
        if any(kw in msg_lower for kw in ("unable to get local issuer", "incomplete chain", "verify chain", "unable to verify")):
            return f"CHAIN_INCOMPLETE:{msg}"
        if "expired" in msg_lower:
            return f"EXPIRED:{msg}"
        return f"TLS_ERROR:{msg}"

    async def _run(self, domain: str) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)
        endpoints: list[WebmailEndpoint] = []
        tls_errors: list[tuple[str, str]] = []  # (host, error_msg)

        # Build candidate URLs: domain + webmail subdomains
        candidate_hosts = [domain] + [f"{sub}.{domain}" for sub in _WEBMAIL_SUBDOMAINS]

        from app.core.config import settings
        http_timeout = settings.WEBMAIL_REQUEST_TIMEOUT

        # PinnedDNSTransport: every TCP connect (initial + redirects) calls
        # SSRFGuard.resolve_and_validate, pins to the validated IP, and never
        # touches the OS resolver — closes the DNS rebinding TOCTOU window.
        # event_hooks remain as defence-in-depth (early hostname rejection before
        # httpcore even attempts the connection).
        pinned_transport = PinnedDNSTransport(ssrf_guard=self._ssrf_guard, verify=False)
        async with httpx.AsyncClient(
            transport=pinned_transport,
            follow_redirects=True,
            max_redirects=settings.WEBMAIL_FOLLOW_REDIRECTS,
            timeout=http_timeout,
            event_hooks={"request": [self._ssrf_redirect_hook]},
        ) as client:
            for host in candidate_hosts[:settings.WEBMAIL_MAX_SUBDOMAINS + 1]:
                # TLS certificate check (separate verify=True client)
                tls_err = await self._check_tls_host(host, min(http_timeout, 8.0))
                if tls_err:
                    tls_errors.append((host, tls_err))

                # Content probe
                discovered = await self._probe_host(client, host, domain)
                endpoints.extend(discovered)

        # Deduplicate by product+host
        seen: set[str] = set()
        unique_endpoints: list[WebmailEndpoint] = []
        for ep in endpoints:
            key = f"{urlparse(ep.url).netloc}:{ep.product}"
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)

        # Emit TLS findings for all hosts with cert errors
        for host, tls_err in tls_errors:
            self._emit_tls_finding(result, host, tls_err)

        # Generate findings for discovered endpoints
        for ep in unique_endpoints:
            if ep.confidence >= 0.5:
                self._emit_discovery_finding(result, ep)
                self._emit_security_header_findings(result, ep)
                self._emit_cookie_findings(result, ep)
                self._emit_info_disclosure_findings(result, ep)

        result.metadata["endpoints_discovered"] = len(unique_endpoints)
        result.metadata["probed_hosts"] = candidate_hosts[:settings.WEBMAIL_MAX_SUBDOMAINS + 1]
        return result

    async def _probe_host(
        self,
        client: httpx.AsyncClient,
        host: str,
        origin_domain: str,
    ) -> list[WebmailEndpoint]:
        """Probe a single host for webmail paths. Returns discovered endpoints."""
        endpoints: list[WebmailEndpoint] = []

        # Validate host via SSRF guard before any HTTP request
        try:
            await self._ssrf_guard.validate_domain_for_scan(host)
        except SSRFGuardError as e:
            self.logger.debug("ssrf_guard_blocked_host", host=host, reason=str(e))
            return []

        for path, candidate_product, min_confidence in _PROBE_PATHS:
            url = f"https://{host}{path}"
            ep = await self._probe_url(client, url, candidate_product, min_confidence)
            if ep and ep.confidence >= 0.4:
                endpoints.append(ep)
                # Once we find a confirmed product at a path, skip root probe for that host
                if path != "/" and ep.confidence >= 0.7:
                    break

        return endpoints

    async def _probe_url(
        self,
        client: httpx.AsyncClient,
        url: str,
        candidate_product: str,
        min_confidence: float,
    ) -> Optional[WebmailEndpoint]:
        """Single URL probe. Returns WebmailEndpoint or None on non-interesting responses."""
        try:
            resp = await client.get(url, headers={"User-Agent": SCANNER_USER_AGENT})
        except SSRFGuardError:
            # Redirect destination blocked by SSRF guard (via event hook)
            return None
        except httpx.ConnectError:
            # Host unreachable or connection refused — normal for most subdomains
            return None
        except httpx.TimeoutException:
            return None
        except Exception as exc:
            self.logger.debug("probe_error", url=url, error=type(exc).__name__)
            return None

        if resp.status_code not in (200, 301, 302, 303, 401, 403, 407):
            return None

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = ""
        try:
            body = resp.text[:8192]  # cap body read for fingerprinting
        except Exception:
            pass

        product, confidence, signals = self._fingerprint(
            candidate_product, str(resp.url), headers, body, resp.status_code
        )

        redirect_chain = [str(r.url) for r in resp.history]

        return WebmailEndpoint(
            url=str(resp.url),
            product=product,
            version=self._extract_version(product, headers, body),
            confidence=confidence,
            status_code=resp.status_code,
            redirect_chain=redirect_chain,
            headers=headers,
            fingerprint_signals=signals,
        )

    def _fingerprint(
        self,
        candidate: str,
        url: str,
        headers: dict[str, str],
        body: str,
        status_code: int,
    ) -> tuple[str, float, list[str]]:
        """Return (product, confidence, signals_matched)."""
        product_scores: dict[str, float] = {}
        signals: list[str] = []

        for rule in _FINGERPRINT_RULES:
            if rule["type"] == "header":
                header_val = headers.get(rule["name"].lower(), "")
                if header_val and re.search(rule["pattern"], header_val):
                    p = rule["product"] or candidate
                    product_scores[p] = max(product_scores.get(p, 0.0), rule["weight"])
                    signals.append(f"header:{rule['name']}={header_val[:80]}")
            elif rule["type"] == "body" and body:
                if re.search(rule["pattern"], body[:8192]):
                    p = rule["product"] or candidate
                    product_scores[p] = max(product_scores.get(p, 0.0), rule["weight"])
                    signals.append(f"body:{rule['pattern'][:40]}")

        # Path-based bonus for the candidate product
        if candidate != "Unknown" and status_code in (200, 401, 403):
            cur = product_scores.get(candidate, 0.0)
            if cur < 0.4:
                product_scores[candidate] = max(cur, 0.3)

        if not product_scores:
            return "Unknown", 0.1, signals

        best_product = max(product_scores, key=lambda k: product_scores[k])
        return best_product, round(product_scores[best_product], 2), signals

    def _extract_version(
        self, product: str, headers: dict[str, str], body: str
    ) -> Optional[str]:
        """Extract version string where possible. Conservative — None if uncertain."""
        if product == "Microsoft OWA":
            v = headers.get("x-owa-version")
            if v:
                return v.strip()
        if product == "SOGo":
            v = headers.get("x-sogo-version")
            if v:
                return v.strip()
        # Roundcube version sometimes leaks in meta generator
        if product == "Roundcube" and body:
            m = re.search(r'(?i)Roundcube\s+Webmail\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)', body)
            if m:
                return m.group(1)
        # Generic: Server header may contain version
        server = headers.get("server", "")
        m = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', server)
        if m and any(p.lower() in server.lower() for p in ["roundcube", "zimbra", "horde"]):
            return m.group(1)
        return None

    def _emit_discovery_finding(self, result: EngineResult, ep: WebmailEndpoint) -> None:
        evidence = [
            Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"HTTP {ep.status_code} at {ep.url}",
                source=ep.url,
                technical_details={
                    "status_code": ep.status_code,
                    "product": ep.product,
                    "version": ep.version,
                    "confidence": ep.confidence,
                    "fingerprint_signals": ep.fingerprint_signals,
                    "redirect_chain": ep.redirect_chain,
                },
            )
        ]
        risk = RiskLevel.INFO
        if ep.version:
            risk = RiskLevel.LOW  # version exposed = at least low
        result.add_finding(self._make_finding(
            check_id="WM-001",
            title=f"Webmail interface identified: {ep.product}",
            description=(
                f"{ep.product} webmail interface detected at {ep.url}. "
                f"Confidence: {ep.confidence:.0%}. "
                + (f"Version: {ep.version}. " if ep.version else "Version not identified. ")
                + "Exposed webmail interfaces expand the email attack surface."
            ),
            risk_level=risk,
            confidence=ep.confidence,
            evidence=evidence,
            remediation=(
                "Restrict webmail access to authorized IP ranges or VPN where possible. "
                "Ensure the application is kept up to date. "
                "Review and harden HTTP security headers."
            ),
            affected_asset=ep.url,
            business_impact="Exposed webmail is a primary target for credential theft and phishing.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))

    def _emit_security_header_findings(self, result: EngineResult, ep: WebmailEndpoint) -> None:
        for header_name, label, _, missing_severity in _SECURITY_HEADERS:
            present = header_name.lower() in ep.headers
            if not present:
                result.add_finding(self._make_finding(
                    check_id=f"WM-SEC-{label.upper().replace('-', '_').replace(' ', '_')}",
                    title=f"Missing {label} header on {ep.product} at {urlparse(ep.url).netloc}",
                    description=(
                        f"The HTTP response from {ep.url} is missing the {header_name} header. "
                        f"This weakens the security posture of the webmail interface."
                    ),
                    risk_level=_RISK_MAP.get(missing_severity, RiskLevel.INFO),
                    confidence=0.95,
                    evidence=[Evidence(
                        type=EvidenceType.HTTP_HEADER,
                        observed_value=f"{header_name}: (absent)",
                        expected_value=f"{header_name}: <secure value>",
                        source=ep.url,
                        technical_details={"url": ep.url, "header": header_name},
                    )],
                    remediation=f"Add the {header_name} header to all responses from this endpoint.",
                    affected_asset=ep.url,
                ))

    def _emit_tls_finding(self, result: EngineResult, host: str, error_msg: str) -> None:
        """Emit a TLS finding with check_id and severity based on error classification.

        error_msg format: "PREFIX:detail" where PREFIX is one of:
          EXPIRED, HOSTNAME_MISMATCH, SELF_SIGNED, CHAIN_INCOMPLETE, TLS_ERROR
        """
        if error_msg.startswith("EXPIRED:"):
            check_id, risk = "WM-TLS-EXPIRED", RiskLevel.HIGH
            title = f"TLS certificate expired at {host}"
            description = (
                f"The TLS certificate for {host} has expired. "
                "Browsers will warn users, and clients enforcing strict TLS will reject connections."
            )
            remediation = "Renew the TLS certificate immediately. Consider automated renewal via ACME/Let's Encrypt."
        elif error_msg.startswith("HOSTNAME_MISMATCH:"):
            check_id, risk = "WM-TLS-HOSTNAME", RiskLevel.MEDIUM
            title = f"TLS certificate hostname mismatch at {host}"
            description = (
                f"The TLS certificate served by {host} does not match the hostname. "
                "This may indicate a misconfigured certificate or a MitM scenario."
            )
            remediation = "Issue a certificate with the correct CN or a SAN entry for this hostname."
        elif error_msg.startswith("SELF_SIGNED:"):
            check_id, risk = "WM-TLS-SELF-SIGNED", RiskLevel.MEDIUM
            title = f"TLS self-signed certificate at {host}"
            description = (
                f"The TLS certificate for {host} is self-signed and not trusted by public CAs. "
                "Users receive security warnings; connections are vulnerable to MitM if users bypass them."
            )
            remediation = "Replace the self-signed certificate with one issued by a trusted CA."
        elif error_msg.startswith("CHAIN_INCOMPLETE:"):
            check_id, risk = "WM-TLS-CHAIN", RiskLevel.MEDIUM
            title = f"Incomplete TLS certificate chain at {host}"
            description = (
                f"The TLS certificate chain for {host} is incomplete or unverifiable. "
                "Intermediate CA certificates may be missing."
            )
            remediation = "Configure the server to send the full certificate chain including all intermediates."
        else:
            check_id, risk = "WM-TLS-CERT", RiskLevel.HIGH
            title = f"TLS certificate validation failure at {host}"
            description = (
                f"HTTPS connection to {host} failed certificate validation. "
                "An invalid certificate exposes users to man-in-the-middle attacks."
            )
            remediation = (
                "Renew or replace the TLS certificate with a valid, CA-signed certificate. "
                "Ensure the certificate CN or SAN matches the hostname."
            )

        detail = error_msg.split(":", 1)[1] if ":" in error_msg else error_msg
        result.add_finding(self._make_finding(
            check_id=check_id,
            title=title,
            description=description,
            risk_level=risk,
            confidence=0.95,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=f"TLS error: {detail[:200]}",
                expected_value="Valid TLS certificate with trusted CA signature",
                source=f"https://{host}/",
                technical_details={"host": host, "tls_error": detail[:500], "classification": check_id},
            )],
            remediation=remediation,
            affected_asset=f"https://{host}/",
            business_impact=(
                "Invalid TLS certificates expose users to credential theft via man-in-the-middle attacks."
            ),
        ))

    def _emit_cookie_findings(self, result: EngineResult, ep: WebmailEndpoint) -> None:
        """Check Set-Cookie headers for missing Secure, HttpOnly, and SameSite attributes."""
        cookies_raw: list[str] = []
        for key, val in ep.headers.items():
            if key.lower() == "set-cookie":
                cookies_raw.append(val)

        if not cookies_raw:
            return

        for cookie_str in cookies_raw:
            cookie_lower = cookie_str.lower()
            cookie_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else cookie_str[:40]

            # Calibrate severity by cookie type:
            #   session/auth  → Secure=HIGH, HttpOnly=HIGH, SameSite=MEDIUM
            #   analytics     → all LOW/INFO (minimal credential impact)
            #   unknown       → Secure=MEDIUM, HttpOnly=MEDIUM, SameSite=MEDIUM
            if _SESSION_COOKIE_RE.match(cookie_name):
                secure_risk, httponly_risk, samesite_risk = (
                    RiskLevel.HIGH, RiskLevel.HIGH, RiskLevel.MEDIUM
                )
                cookie_class = "session/auth"
            elif _ANALYTICS_COOKIE_RE.match(cookie_name):
                secure_risk, httponly_risk, samesite_risk = (
                    RiskLevel.LOW, RiskLevel.LOW, RiskLevel.INFO
                )
                cookie_class = "analytics/tracking"
            else:
                secure_risk, httponly_risk, samesite_risk = (
                    RiskLevel.MEDIUM, RiskLevel.MEDIUM, RiskLevel.MEDIUM
                )
                cookie_class = "unknown"

            if "secure" not in cookie_lower:
                result.add_finding(self._make_finding(
                    check_id="WM-COOKIE-SECURE",
                    title=f"Cookie missing Secure flag on {ep.product} at {urlparse(ep.url).netloc}",
                    description=(
                        f"The Set-Cookie header for '{cookie_name}' ({cookie_class}) at {ep.url} "
                        "lacks the Secure flag. Without Secure, the cookie may be sent over "
                        "unencrypted HTTP connections."
                    ),
                    risk_level=secure_risk,
                    confidence=0.9,
                    evidence=[Evidence(
                        type=EvidenceType.HTTP_HEADER,
                        observed_value=f"Set-Cookie: {cookie_str[:120]}",
                        expected_value="Set-Cookie: ...; Secure",
                        source=ep.url,
                        technical_details={
                            "cookie_name": cookie_name,
                            "cookie_class": cookie_class,
                            "attribute": "Secure",
                        },
                    )],
                    remediation="Add the Secure attribute to all authentication and session cookies.",
                    affected_asset=ep.url,
                ))

            if "httponly" not in cookie_lower:
                result.add_finding(self._make_finding(
                    check_id="WM-COOKIE-HTTPONLY",
                    title=f"Cookie missing HttpOnly flag on {ep.product} at {urlparse(ep.url).netloc}",
                    description=(
                        f"The Set-Cookie header for '{cookie_name}' ({cookie_class}) at {ep.url} "
                        "lacks the HttpOnly flag. Without HttpOnly, the cookie is accessible via "
                        "JavaScript, increasing XSS impact."
                    ),
                    risk_level=httponly_risk,
                    confidence=0.9,
                    evidence=[Evidence(
                        type=EvidenceType.HTTP_HEADER,
                        observed_value=f"Set-Cookie: {cookie_str[:120]}",
                        expected_value="Set-Cookie: ...; HttpOnly",
                        source=ep.url,
                        technical_details={
                            "cookie_name": cookie_name,
                            "cookie_class": cookie_class,
                            "attribute": "HttpOnly",
                        },
                    )],
                    remediation="Add the HttpOnly attribute to all authentication and session cookies.",
                    affected_asset=ep.url,
                ))

            if "samesite" not in cookie_lower:
                result.add_finding(self._make_finding(
                    check_id="WM-COOKIE-SAMESITE",
                    title=f"Cookie missing SameSite attribute on {ep.product} at {urlparse(ep.url).netloc}",
                    description=(
                        f"The Set-Cookie header for '{cookie_name}' ({cookie_class}) at {ep.url} "
                        "lacks the SameSite attribute. Without SameSite=Strict or Lax, cookies are "
                        "sent with cross-origin requests (CSRF risk)."
                    ),
                    risk_level=samesite_risk,
                    confidence=0.9,
                    evidence=[Evidence(
                        type=EvidenceType.HTTP_HEADER,
                        observed_value=f"Set-Cookie: {cookie_str[:120]}",
                        expected_value="Set-Cookie: ...; SameSite=Strict",
                        source=ep.url,
                        technical_details={
                            "cookie_name": cookie_name,
                            "cookie_class": cookie_class,
                            "attribute": "SameSite",
                        },
                    )],
                    remediation="Add SameSite=Strict (or Lax) to all authentication and session cookies.",
                    affected_asset=ep.url,
                ))

    def _emit_info_disclosure_findings(self, result: EngineResult, ep: WebmailEndpoint) -> None:
        for header_name in _SENSITIVE_HEADERS:
            val = ep.headers.get(header_name.lower())
            if val:
                result.add_finding(self._make_finding(
                    check_id="WM-DISCLOSURE-HEADER",
                    title=f"Sensitive header exposed: {header_name} at {urlparse(ep.url).netloc}",
                    description=(
                        f"The server response includes the {header_name} header with value '{val[:120]}'. "
                        "This may disclose technology stack information useful to attackers."
                    ),
                    risk_level=RiskLevel.LOW,
                    confidence=0.9,
                    evidence=[Evidence(
                        type=EvidenceType.HTTP_HEADER,
                        observed_value=f"{header_name}: {val[:120]}",
                        expected_value=f"{header_name}: (removed)",
                        source=ep.url,
                        technical_details={"header": header_name, "value": val[:120]},
                    )],
                    remediation=f"Remove or suppress the {header_name} header from server responses.",
                    affected_asset=ep.url,
                ))
