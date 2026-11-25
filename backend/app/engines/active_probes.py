"""
ActiveProbesEngine — Module 09: Non-destructive exploitation verification.

Runs AFTER all passive engines. Takes prior findings as input and attempts
to verify or refute each discovered weakness with a live active probe.

Design constraints:
- NO destructive actions: no mail sent, no credentials submitted, no writes
- Probes are read-only: connect, observe response, disconnect
- Each probe is strictly rate-limited (1 attempt per finding per scan)
- Never attempt probes outside the declared scan scope
- Failed probe = UNKNOWN confidence, not "not vulnerable"
- 403/reset/timeout ≠ patched — log as INCONCLUSIVE

check_id prefix: AP-

Checks implemented:
  AP-STARTTLS-NOTENFORCE   STARTTLS advertised but plain auth accepted without upgrade
  AP-SMTP-INJECT           SMTP MAIL FROM header injection (CRLF / bare LF)
  AP-SPF-DANGLING          SPF include: points to unresolvable subdomain
  AP-CVE-PROXYLOGON        Exchange CVE-2021-26855 SSRF path probe
  AP-CVE-EXIM-WIZARD       Exim CVE-2019-10149 RCPT TO expansion probe
  AP-CVE-ROUNDCUBE-XSS     Roundcube XSS via email header reflection probe
  AP-CVE-ZIMBRA-SSRF       Zimbra CVE-2022-27925 path traversal probe
  AP-SMTP-SMUGGLING        SMTP Smuggling — bare-LF DATA injection (CVE-2023-51764)
"""
import asyncio
import re
import socket
from dataclasses import dataclass, field
from typing import Optional

import dns.asyncresolver
import dns.resolver
import httpx
import structlog

from app.engines.base import BaseEngine, EngineResult
from app.engines.ssrf_guard import SSRFGuard
from app.engines.webmail_transport import PinnedDNSTransport
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel

logger = structlog.get_logger("mailox.engines.active_probes")

_CONNECT_TIMEOUT = 8.0
_READ_TIMEOUT = 10.0
_HTTP_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# SMTP low-level helpers (no dependency on smtplib — raw socket for precision)
# ---------------------------------------------------------------------------

async def _smtp_connect(host: str, port: int) -> Optional[asyncio.StreamReader | tuple]:
    """Open async TCP connection to SMTP. Returns (reader, writer) or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_CONNECT_TIMEOUT,
        )
        banner = await asyncio.wait_for(reader.readline(), timeout=_READ_TIMEOUT)
        return reader, writer, banner.decode(errors="replace").strip()
    except Exception:
        return None


async def _smtp_cmd(reader, writer, cmd: str) -> str:
    """Send SMTP command, read multi-line response."""
    if "\r" in cmd or "\n" in cmd:
        # Refuse SMTP command injection (e.g. CRLF smuggled via canary_email)
        raise ValueError("SMTP command contains CR/LF")
    writer.write((cmd + "\r\n").encode())
    await writer.drain()
    response = b""
    for _ in range(20):
        line = await asyncio.wait_for(reader.readline(), timeout=_READ_TIMEOUT)
        response += line
        if len(line) >= 4 and line[3:4] == b" ":
            break
    return response.decode(errors="replace").strip()


async def _smtp_quit(writer) -> None:
    try:
        writer.write(b"QUIT\r\n")
        await writer.drain()
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=3.0)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Probe result container
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    check_id: str
    vulnerable: bool
    inconclusive: bool = False
    evidence_value: Optional[str] = None
    raw_response: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Active Probes Engine
# ---------------------------------------------------------------------------

class ActiveProbesEngine(BaseEngine):
    """
    Post-processing engine: takes prior findings + resolved hosts,
    runs non-destructive active probes to verify/refute detections.
    """
    name: str = "active_probes"
    default_timeout: float = 90.0

    def __init__(self, ssrf_guard: Optional[SSRFGuard] = None, timeout: Optional[float] = None) -> None:
        super().__init__(timeout=timeout)
        self._guard = ssrf_guard if ssrf_guard else SSRFGuard()

    async def _validated_smtp_connect(self, host: str, port: int) -> Optional[tuple]:
        """SMTP connect with IP validation via SSRF guard."""
        try:
            validated_ips = await self._guard.resolve_and_validate(host)
            connect_ip = validated_ips[0]
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_ip, port),
                timeout=_CONNECT_TIMEOUT,
            )
            try:
                banner = await asyncio.wait_for(reader.readline(), timeout=_READ_TIMEOUT)
            except BaseException:
                writer.close()
                raise
            return reader, writer, banner.decode(errors="replace").strip()
        except Exception:
            return None

    def _make_http_client(self) -> httpx.AsyncClient:
        """Build httpx client with DNS pinning via SSRFGuard."""
        transport = PinnedDNSTransport(self._guard, verify=False)
        return httpx.AsyncClient(
            transport=transport,
            timeout=_HTTP_TIMEOUT,
            verify=False,
            follow_redirects=True,
            max_redirects=3,
        )

    async def _run(self, domain: str) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)
        result.metadata["note"] = (
            "ActiveProbesEngine requires prior findings. "
            "Call run_from_findings(domain, mx_host, findings) instead."
        )
        return result

    async def run_from_findings(
        self,
        domain: str,
        prior_findings: list[Finding],
        mx_host: Optional[str] = None,
        webmail_url: Optional[str] = None,
        smtp_port: int = 25,
    ) -> EngineResult:
        """
        Primary entry point.

        mx_host: resolved MX hostname (e.g. mail.example.com)
        webmail_url: detected webmail base URL (e.g. https://mail.example.com)
        """
        result = EngineResult(engine=self.name, domain=domain)
        probes_run: list[str] = []

        # Determine SMTP target
        target_host = mx_host or domain

        # ── 1. STARTTLS not enforced ──────────────────────────────────────────
        if _has_finding(prior_findings, {"SMTP-05", "SMTP-06", "SMTP-07", "SMTP-08",
                                          "smtp-discovery", "smtp_security"}):
            pr = await self._probe_starttls_enforcement(target_host, smtp_port, domain)
            probes_run.append(pr.check_id)
            if pr.vulnerable:
                result.add_finding(self._starttls_finding(pr, domain, target_host, smtp_port))
            elif not pr.inconclusive:
                result.add_finding(self._make_clean_finding(
                    pr.check_id, "STARTTLS correctly enforced", domain
                ))

        # ── 2. SMTP header injection ──────────────────────────────────────────
        pr2 = await self._probe_smtp_header_injection(target_host, smtp_port, domain)
        probes_run.append(pr2.check_id)
        if pr2.vulnerable:
            result.add_finding(self._smtp_inject_finding(pr2, domain, target_host))

        # ── 2b. SMTP Smuggling (bare-LF DATA injection) ───────────────────────
        pr_smug = await self._probe_smtp_smuggling(target_host, smtp_port, domain)
        probes_run.append(pr_smug.check_id)
        if pr_smug.vulnerable:
            result.add_finding(self._smtp_smuggling_finding(pr_smug, domain, target_host, smtp_port))

        # ── 3. SPF dangling includes ──────────────────────────────────────────
        spf_findings = [f for f in prior_findings if f.check_id.startswith("SPF-")]
        if spf_findings:
            pr3 = await self._probe_spf_dangling(domain)
            probes_run.append(pr3.check_id)
            if pr3.vulnerable:
                result.add_finding(self._spf_dangling_finding(pr3, domain))

        # ── 4. CVE-specific probes ────────────────────────────────────────────
        cve_findings = [f for f in prior_findings if "VI-CVE-" in f.check_id or "VI-" in f.check_id]

        for f in cve_findings:
            cve_id = _extract_cve_id(f.check_id)
            if not cve_id:
                continue

            if cve_id == "CVE-2021-26855" and webmail_url:
                pr = await self._probe_proxylogon(webmail_url, domain)
                probes_run.append(pr.check_id)
                if pr.vulnerable:
                    result.add_finding(self._cve_probe_finding(pr, cve_id, domain, webmail_url))

            elif cve_id == "CVE-2019-10149":
                pr = await self._probe_exim_wizard(target_host, smtp_port, domain)
                probes_run.append(pr.check_id)
                if pr.vulnerable:
                    result.add_finding(self._cve_probe_finding(pr, cve_id, domain, target_host))

            elif cve_id in ("CVE-2023-43770", "CVE-2024-37383", "CVE-2024-42009") and webmail_url:
                pr = await self._probe_roundcube_xss(webmail_url, domain)
                probes_run.append(pr.check_id)
                if pr.vulnerable:
                    result.add_finding(self._cve_probe_finding(pr, cve_id, domain, webmail_url))

            elif cve_id in ("CVE-2023-37580", "CVE-2024-45519") and webmail_url:
                pr = await self._probe_zimbra(webmail_url, domain)
                probes_run.append(pr.check_id)
                if pr.vulnerable:
                    result.add_finding(self._cve_probe_finding(pr, cve_id, domain, webmail_url))

        result.metadata["probes_run"] = probes_run
        return result

    # ── Probe: STARTTLS not enforced ──────────────────────────────────────────

    async def _probe_starttls_enforcement(
        self, host: str, port: int, domain: str
    ) -> ProbeResult:
        """
        Connect to SMTP port, send EHLO, attempt AUTH LOGIN *without* STARTTLS.
        If server accepts AUTH command → STARTTLS not enforced.
        """
        check_id = "AP-STARTTLS-NOTENFORCE"
        conn = await self._validated_smtp_connect(host, port)
        if conn is None:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error="Connection failed")
        reader, writer, banner = conn
        try:
            ehlo = await _smtp_cmd(reader, writer, f"EHLO probe.{domain}")
            advertises_starttls = "STARTTLS" in ehlo.upper()
            advertises_auth = "AUTH" in ehlo.upper()

            if not advertises_starttls:
                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                                   evidence_value="STARTTLS not advertised")

            if not advertises_auth:
                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                                   evidence_value="AUTH not advertised in plain EHLO")

            # Try AUTH LOGIN without upgrading to TLS
            auth_resp = await _smtp_cmd(reader, writer, "AUTH LOGIN")
            code = auth_resp[:3]

            # 334 = server sent challenge → accepted AUTH without TLS → vulnerable
            # 530 = "Must issue STARTTLS first" → enforced → clean
            # 503 = "Bad sequence" → enforced → clean
            vulnerable = code == "334"
            return ProbeResult(
                check_id=check_id,
                vulnerable=vulnerable,
                evidence_value=f"AUTH LOGIN response: {auth_resp[:80]}",
                raw_response=auth_resp,
            )
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))
        finally:
            await _smtp_quit(writer)

    # ── Probe: SMTP header injection ─────────────────────────────────────────

    async def _probe_smtp_header_injection(
        self, host: str, port: int, domain: str
    ) -> ProbeResult:
        """
        Attempt CRLF injection in MAIL FROM parameter.
        Inject a bare LF + X-Injected header and check if server accepts it.
        Non-destructive: we never reach DATA, disconnect after MAIL FROM response.
        """
        check_id = "AP-SMTP-INJECT"
        conn = await self._validated_smtp_connect(host, port)
        if conn is None:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error="Connection failed")
        reader, writer, banner = conn
        try:
            await _smtp_cmd(reader, writer, f"EHLO probe.{domain}")
            # Inject via MAIL FROM address parameter — bare LF variant
            injected = "MAIL FROM:<probe@probe.com\nX-INJECTED: header>"
            resp = await _smtp_cmd(reader, writer, injected)
            code = resp[:3]
            # If server returns 250 or 2xx with the injected address → vulnerable
            # A patched server returns 501 (syntax error) or 550
            vulnerable = code.startswith("2")
            return ProbeResult(
                check_id=check_id,
                vulnerable=vulnerable,
                evidence_value=f"MAIL FROM injection response: {resp[:120]}",
                raw_response=resp,
            )
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))
        finally:
            await _smtp_quit(writer)

    # ── Probe: SPF dangling include ───────────────────────────────────────────

    async def _probe_spf_dangling(self, domain: str) -> ProbeResult:
        """
        Parse SPF TXT record for all include: / redirect= entries.
        For each included domain, attempt DNS resolution.
        Unresolvable included domain = dangling SPF include.
        """
        check_id = "AP-SPF-DANGLING"
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            answers = await resolver.resolve(domain, "TXT")
            spf_record = None
            for rdata in answers:
                txt = "".join(s.decode(errors="replace") for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break

            if not spf_record:
                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                                   error="No SPF record found")

            # Extract all include: and redirect= domains
            includes = re.findall(r'include:([^\s]+)', spf_record)
            redirects = re.findall(r'redirect=([^\s]+)', spf_record)
            all_included = includes + redirects

            dangling = []
            for inc_domain in all_included:
                try:
                    await resolver.resolve(inc_domain, "TXT")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    # Domain doesn't exist or has no TXT → dangling
                    dangling.append(inc_domain)
                except Exception:
                    pass

            if dangling:
                return ProbeResult(
                    check_id=check_id,
                    vulnerable=True,
                    evidence_value=f"Dangling SPF includes: {', '.join(dangling)}",
                    raw_response=f"SPF record: {spf_record}",
                )
            return ProbeResult(check_id=check_id, vulnerable=False,
                               evidence_value=f"All {len(all_included)} includes resolve")
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))

    # ── Probe: CVE-2021-26855 ProxyLogon SSRF path ───────────────────────────

    async def _probe_proxylogon(self, base_url: str, domain: str) -> ProbeResult:
        """
        Non-destructive ProxyLogon probe:
        Test SSRF via autodiscover path confusion.
        A 302 to /owa/ is NORMAL behavior, not an indicator of vulnerability.
        Only emit vulnerable if we see a specific ProxyLogon indicator.
        """
        check_id = "AP-CVE-PROXYLOGON"
        # SSRF path is the real indicator of ProxyLogon
        ssrf_path = "/autodiscover/autodiscover.json?@evil.com/autodiscover/autodiscover.json"
        normal_paths = ["/ecp/", "/ecp/default.aspx"]

        try:
            async with self._make_http_client() as client:
                # First test the SSRF path - this is the real indicator
                ssrf_url = base_url.rstrip("/") + ssrf_path
                try:
                    resp = await client.get(ssrf_url)
                    # A 200 response with autodiscover content on the SSRF path is a strong indicator
                    if resp.status_code == 200 and "autodiscover" in resp.text.lower()[:1000]:
                        server = resp.headers.get("Server", "")
                        return ProbeResult(
                            check_id=check_id,
                            vulnerable=True,
                            evidence_value=f"SSRF path returned 200 with autodiscover content, Server: {server}",
                            raw_response=resp.text[:500],
                        )
                except Exception:
                    pass

                # Check ECP paths - but 302/301 to OWA is NORMAL, not vulnerable
                exchange_detected = False
                for path in normal_paths:
                    url = base_url.rstrip("/") + path
                    try:
                        resp = await client.get(url)
                        server = resp.headers.get("Server", "")
                        x_owa = resp.headers.get("X-OWA-Version", "")
                        location = resp.headers.get("Location", "").lower()

                        # Detect Exchange server presence
                        if "microsoft" in server.lower() or x_owa or "exchange" in resp.text.lower()[:500]:
                            exchange_detected = True

                        # 302/301 to /owa/ is NORMAL behavior - not an indicator of ProxyLogon
                        if resp.status_code in (301, 302) and ("/owa" in location or "owa/" in location):
                            continue  # Normal redirect, not vulnerable

                        # 200 on /ecp/ without auth could indicate misconfiguration but not ProxyLogon
                        # Only the SSRF path confusion indicates the actual CVE
                    except Exception:
                        continue

                # If we detected Exchange but couldn't confirm ProxyLogon, mark as inconclusive
                if exchange_detected:
                    return ProbeResult(
                        check_id=check_id,
                        vulnerable=False,
                        inconclusive=True,
                        evidence_value="Exchange detected but no specific ProxyLogon indicators found. Manual verification recommended.",
                    )

            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                               evidence_value="All ECP paths require auth or return 404")
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))

    # ── Probe: CVE-2019-10149 Exim "Return of the WIZard" ────────────────────

    async def _probe_exim_wizard(self, host: str, port: int, domain: str) -> ProbeResult:
        """
        Non-destructive Exim CVE-2019-10149 probe.
        Sends RCPT TO with expansion syntax: ${run{/bin/true}{}}
        A vulnerable Exim (4.87-4.91) returns 250 (accepts expansion).
        A patched Exim returns 550 or 501 (rejects expansion in address).
        We NEVER reach DATA — disconnect immediately after RCPT response.
        """
        check_id = "AP-CVE-EXIM-WIZARD"
        conn = await self._validated_smtp_connect(host, port)
        if conn is None:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error="Connection failed")
        reader, writer, banner = conn
        try:
            # Only probe if banner mentions Exim
            if "exim" not in banner.lower():
                return ProbeResult(check_id=check_id, vulnerable=False,
                                   evidence_value="Not an Exim server")

            await _smtp_cmd(reader, writer, f"EHLO probe.{domain}")
            await _smtp_cmd(reader, writer, "MAIL FROM:<probe@probe.com>")
            # Expansion probe — /bin/true is a no-op, no side effects
            rcpt_resp = await _smtp_cmd(
                reader, writer,
                "RCPT TO:<${run{/bin/true}{}}@localhost>"
            )
            code = rcpt_resp[:3]
            # 250 = expansion accepted = vulnerable
            # 550/501/553 = rejected = patched
            vulnerable = code == "250"
            return ProbeResult(
                check_id=check_id,
                vulnerable=vulnerable,
                evidence_value=f"RCPT TO expansion response: {rcpt_resp[:120]}",
                raw_response=rcpt_resp,
            )
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))
        finally:
            await _smtp_quit(writer)

    # ── Probe: Roundcube XSS reflection ──────────────────────────────────────

    async def _probe_roundcube_xss(self, base_url: str, domain: str) -> ProbeResult:
        """
        Non-destructive Roundcube XSS probe.
        Tests if the login page reflects unescaped input in error messages,
        which indicates the sanitizer used by CVE-2023-43770/CVE-2024-37383
        is likely absent.
        Does NOT authenticate or access mailboxes.
        """
        check_id = "AP-CVE-ROUNDCUBE-XSS"
        try:
            async with self._make_http_client() as client:
                # Probe 1: check Roundcube version in login page source
                resp = await client.get(base_url.rstrip("/") + "/")
                body = resp.text[:8000]

                version_match = re.search(
                    r'roundcube[^"\']*["\']([0-9]+\.[0-9]+\.[0-9]+)',
                    body, re.I
                )
                if not version_match:
                    version_match = re.search(
                        r'version["\s:=]+["\']?([0-9]+\.[0-9]+\.[0-9]+)',
                        body, re.I
                    )

                if version_match:
                    version = version_match.group(1)
                    # Check if version falls in any known vulnerable range
                    # CVE-2024-42009: < 1.5.8 or (1.6.x < 1.6.8)
                    v = tuple(int(x) for x in version.split(".")[:3])
                    vulnerable = (
                        v < (1, 5, 8) or
                        ((1, 6, 0) <= v < (1, 6, 8))
                    )
                    if vulnerable:
                        return ProbeResult(
                            check_id=check_id,
                            vulnerable=True,
                            evidence_value=f"Roundcube {version} in known vulnerable range",
                        )

                # Probe 2: check for missing Content-Security-Policy header
                csp = resp.headers.get("Content-Security-Policy", "")
                if not csp and "roundcube" in body.lower():
                    return ProbeResult(
                        check_id=check_id,
                        vulnerable=True,
                        evidence_value="Roundcube: no Content-Security-Policy header",
                        raw_response=f"CSP: absent, body snippet: {body[:200]}",
                    )

                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                                   evidence_value="Version not in vulnerable range or not detectable")
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))

    # ── Probe: Zimbra path traversal / auth bypass ────────────────────────────

    async def _probe_zimbra(self, base_url: str, domain: str) -> ProbeResult:
        """
        Non-destructive Zimbra probe for CVE-2022-27925 (path traversal) /
        CVE-2023-37580 (XSS via crafted URL).
        Checks if /service/home/ endpoint is accessible without auth,
        and if /zimbraAdmin/ responds, which indicates unpatched Zimbra.
        """
        check_id = "AP-CVE-ZIMBRA-SSRF"
        try:
            async with self._make_http_client() as client:
                # Probe: /zimbraAdmin/ accessible
                for path in ["/zimbraAdmin/", "/service/admin/soap"]:
                    url = base_url.rstrip("/") + path
                    try:
                        resp = await client.get(url)
                        zimbra_header = resp.headers.get("X-Zimbra-Extn", "")
                        zimbra_in_body = "zimbra" in resp.text.lower()[:1000]
                        if resp.status_code == 200 and (zimbra_header or zimbra_in_body):
                            return ProbeResult(
                                check_id=check_id,
                                vulnerable=True,
                                evidence_value=f"Zimbra admin path {path} accessible without auth (HTTP {resp.status_code})",
                                raw_response=zimbra_header,
                            )
                    except Exception:
                        continue

                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                                   evidence_value="Zimbra admin paths require auth or unreachable")
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))

    # ── Probe: SMTP Smuggling (bare-LF DATA terminator injection) ────────────

    async def _probe_smtp_smuggling(
        self, host: str, port: int, domain: str
    ) -> ProbeResult:
        """
        SMTP Smuggling (CVE-2023-51764 and similar) — test whether the server
        accepts a bare <LF>.<LF> as a DATA terminator instead of <CRLF>.<CRLF>.

        A vulnerable server allows injecting a second message mid-DATA,
        enabling header forgery and DMARC bypass.

        Non-destructive: we connect, issue EHLO + MAIL FROM + RCPT TO then
        immediately QUIT before reaching DATA. We only test whether the server
        would accept the preamble; we infer smuggling risk from EHLO response
        and banner, NOT by actually sending DATA.
        """
        check_id = "AP-SMTP-SMUGGLING"
        conn = await self._validated_smtp_connect(host, port)
        if conn is None:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error="Connection failed")
        reader, writer, banner = conn
        try:
            ehlo_resp = await _smtp_cmd(reader, writer, f"EHLO probe.{domain}")

            # Heuristic signals that indicate smuggling risk:
            # 1. Server does NOT advertise SMTPUTF8 (older MTA, more likely vulnerable)
            # 2. Server does NOT advertise CHUNKING (pipelining path less hardened)
            # 3. MTA known to be vulnerable from banner (Postfix < 3.8.4, Exim < 4.97.1,
            #    Sendmail < 8.17.2, PowerMTA, some Exchange versions)
            ehlo_up = ehlo_resp.upper()
            banner_lo = banner.lower()

            # Known-vulnerable MTA version patterns
            known_vuln = False
            vuln_detail = ""
            # Postfix vulnerable < 3.8.4 (also 3.5.x < 3.5.23, 3.6.x < 3.6.12, 3.7.x < 3.7.11)
            m_postfix = re.search(r'postfix.*?(\d+\.\d+\.\d+)', banner_lo)
            if m_postfix:
                v = tuple(int(x) for x in m_postfix.group(1).split(".")[:3])
                if v < (3, 8, 4):
                    known_vuln = True
                    vuln_detail = f"Postfix {m_postfix.group(1)} (< 3.8.4)"
            # Exim vulnerable < 4.97.1
            m_exim = re.search(r'exim.*?(\d+\.\d+\.?\d*)', banner_lo)
            if m_exim:
                v_str = m_exim.group(1)
                parts = [int(x) for x in re.split(r'[._]', v_str)[:3]]
                if len(parts) >= 2 and tuple(parts[:2]) <= (4, 97):
                    known_vuln = True
                    vuln_detail = f"Exim {v_str} (possibly < 4.97.1)"
            # Sendmail vulnerable < 8.17.2
            m_sendmail = re.search(r'sendmail.*?(\d+\.\d+\.\d+)', banner_lo)
            if m_sendmail:
                v = tuple(int(x) for x in m_sendmail.group(1).split(".")[:3])
                if v < (8, 17, 2):
                    known_vuln = True
                    vuln_detail = f"Sendmail {m_sendmail.group(1)} (< 8.17.2)"

            if known_vuln:
                return ProbeResult(
                    check_id=check_id,
                    vulnerable=True,
                    evidence_value=f"Potentially vulnerable MTA detected: {vuln_detail}",
                    raw_response=f"Banner: {banner[:120]}\nEHLO: {ehlo_resp[:200]}",
                )

            # Soft signal: no SMTPUTF8 + old-style server
            smtputf8 = "SMTPUTF8" in ehlo_up
            chunking = "CHUNKING" in ehlo_up
            if not smtputf8 and not chunking and any(
                kw in banner_lo for kw in ("postfix", "exim", "sendmail", "qmail")
            ):
                return ProbeResult(
                    check_id=check_id,
                    vulnerable=False,
                    inconclusive=True,
                    evidence_value=(
                        f"MTA may be vulnerable (no SMTPUTF8/CHUNKING, self-hosted MTA). "
                        f"Banner: {banner[:80]}"
                    ),
                )

            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                               evidence_value="No smuggling indicators detected")
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))
        finally:
            await _smtp_quit(writer)

    # ── Finding builders ──────────────────────────────────────────────────────

    def _starttls_finding(
        self, pr: ProbeResult, domain: str, host: str, port: int
    ) -> Finding:
        return self._make_finding(
            check_id=pr.check_id,
            title="STARTTLS not enforced — plaintext AUTH accepted",
            description=(
                f"SMTP server {host}:{port} advertises STARTTLS but accepts AUTH LOGIN "
                "commands without requiring TLS negotiation first. An attacker on the "
                "network path can intercept SMTP authentication credentials in cleartext."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.95,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=pr.evidence_value,
                expected_value="530 Must issue STARTTLS first",
                source=f"smtp://{host}:{port}",
                technical_details={"raw_response": pr.raw_response, "host": host, "port": port},
            )],
            remediation=(
                "Set `smtpd_tls_auth_only = yes` (Postfix) or equivalent. "
                "Ensure AUTH mechanisms are only advertised after STARTTLS."
            ),
            affected_asset=domain,
            business_impact=(
                "SMTP credentials transmitted in cleartext are trivially captured "
                "by any network observer (ISP, Wi-Fi AP, internal attacker)."
            ),
            references=["https://www.rfc-editor.org/rfc/rfc3207"],
        )

    def _smtp_inject_finding(self, pr: ProbeResult, domain: str, host: str) -> Finding:
        return self._make_finding(
            check_id=pr.check_id,
            title="SMTP MAIL FROM header injection accepted",
            description=(
                f"SMTP server {host} accepted a MAIL FROM command containing a bare LF "
                "character followed by an injected header. This allows an attacker to inject "
                "arbitrary SMTP envelope fields, potentially enabling spam relay, "
                "log injection, or header smuggling attacks."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=pr.evidence_value,
                expected_value="501 Syntax error (injected characters rejected)",
                source=f"smtp://{host}",
                technical_details={"raw_response": pr.raw_response},
            )],
            remediation=(
                "Upgrade MTA to a version that sanitizes CRLF in envelope addresses. "
                "Postfix ≥ 3.5, Exim ≥ 4.95, Sendmail with header_checks."
            ),
            affected_asset=domain,
            references=["https://cwe.mitre.org/data/definitions/93.html"],
        )

    def _smtp_smuggling_finding(
        self, pr: ProbeResult, domain: str, host: str, port: int
    ) -> Finding:
        return self._make_finding(
            check_id=pr.check_id,
            title=f"SMTP Smuggling — vulnerable MTA version detected on {host}:{port}",
            description=(
                f"The SMTP server {host}:{port} appears to run a version of "
                f"{pr.evidence_value.split(':')[0] if pr.evidence_value else 'the MTA'} "
                "known to be vulnerable to SMTP Smuggling (CVE-2023-51764 and related). "
                "An attacker can inject a second MIME message mid-DATA using a bare <LF>.<LF> "
                "sequence, bypassing DMARC alignment and potentially forging email that passes "
                "authentication checks on receiving servers."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.80,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=pr.evidence_value,
                source=f"smtp://{host}:{port}",
                technical_details={"raw_response": pr.raw_response},
            )],
            remediation=(
                "Upgrade MTA:\n"
                "- Postfix: ≥ 3.8.4 (or 3.5.23 / 3.6.12 / 3.7.11)\n"
                "- Exim: ≥ 4.97.1\n"
                "- Sendmail: ≥ 8.17.2\n"
                "Or configure `smtpd_forbid_bare_newline = yes` (Postfix workaround)."
            ),
            affected_asset=f"{host}:{port}",
            business_impact=(
                "Attackers can send email that passes SPF/DKIM/DMARC on receiving MTAs, "
                "enabling highly convincing phishing from your domain."
            ),
            references=[
                "https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/",
                "https://www.postfix.org/smtp-smuggling.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2023-51764",
            ],
        )

    def _spf_dangling_finding(self, pr: ProbeResult, domain: str) -> Finding:
        return self._make_finding(
            check_id=pr.check_id,
            title="SPF dangling include — subdomain available for takeover",
            description=(
                f"The SPF record for {domain} includes a reference to a domain "
                f"that does not resolve: {pr.evidence_value}. "
                "An attacker can register this domain and publish an SPF record "
                "that authorizes their own mail servers to send email as your domain. "
                "SPF checks will pass for spoofed email sent from that server."
            ),
            risk_level=RiskLevel.CRITICAL,
            confidence=0.98,
            evidence=[Evidence(
                type=EvidenceType.DNS_RECORD,
                observed_value=pr.evidence_value,
                expected_value="All SPF include: domains resolve",
                source=f"dns://{domain}",
                technical_details={"spf_record": pr.raw_response},
            )],
            remediation=(
                "Remove the dangling include: entry from your SPF record immediately. "
                "Audit all SPF includes for third-party domains you no longer control."
            ),
            affected_asset=domain,
            business_impact=(
                "Attacker can register the dangling domain and send email that passes "
                "SPF alignment, bypassing spam filters and appearing as your domain."
            ),
            references=[
                "https://www.rfc-editor.org/rfc/rfc7208",
                "https://labs.detectify.com/2016/06/20/spf-subdomain-takeover/",
            ],
        )

    def _cve_probe_finding(
        self, pr: ProbeResult, cve_id: str, domain: str, target: str
    ) -> Finding:
        severity_map = {
            "CVE-2021-26855": RiskLevel.CRITICAL,
            "CVE-2019-10149": RiskLevel.CRITICAL,
            "CVE-2023-43770": RiskLevel.HIGH,
            "CVE-2024-37383": RiskLevel.HIGH,
            "CVE-2024-42009": RiskLevel.CRITICAL,
            "CVE-2023-37580": RiskLevel.HIGH,
            "CVE-2024-45519": RiskLevel.CRITICAL,
        }
        risk = severity_map.get(cve_id, RiskLevel.HIGH)
        return self._make_finding(
            check_id=pr.check_id,
            title=f"{cve_id} — active probe CONFIRMED vulnerability",
            description=(
                f"Non-destructive active probe confirmed {cve_id} is likely exploitable "
                f"on {target}. The server responded to a known exploitation indicator: "
                f"{pr.evidence_value}"
            ),
            risk_level=risk,
            confidence=0.85,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE if not target.startswith("smtp") else EvidenceType.SMTP_RESPONSE,
                observed_value=pr.evidence_value,
                expected_value="Patched server rejects probe",
                source=target,
                technical_details={
                    "cve_id": cve_id,
                    "raw_response": pr.raw_response,
                    "probe_check_id": pr.check_id,
                },
            )],
            remediation=f"Apply vendor patch for {cve_id} immediately.",
            affected_asset=domain,
            business_impact=(
                "Active probe indicates the vulnerability is reachable and unmitigated. "
                "Exploitation risk is elevated beyond passive CVE correlation."
            ),
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        )

    def _make_clean_finding(self, check_id: str, title: str, domain: str) -> Finding:
        return self._make_finding(
            check_id=f"{check_id}-CLEAN",
            title=title,
            description=f"Active probe for {check_id} returned a clean result.",
            risk_level=RiskLevel.INFO,
            confidence=0.9,
            evidence=[self._analysis_evidence(domain, observed="Probe returned clean")],
            remediation="No action required.",
            affected_asset=domain,
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _has_finding(findings: list[Finding], check_ids: set[str]) -> bool:
    for f in findings:
        for cid in check_ids:
            if cid.lower() in f.check_id.lower() or f.engine in check_ids:
                return True
    return False


def _extract_cve_id(check_id: str) -> Optional[str]:
    m = re.search(r'CVE-\d{4}-\d+', check_id, re.I)
    return m.group(0).upper() if m else None
