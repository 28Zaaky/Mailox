"""
SMTP Discovery Engine — MX records, banner grab, ESMTP capabilities, STARTTLS, open relay probe.

Security constraints:
- Open relay probe: NO actual message delivery, NO third-party addresses
- TOCTOU prevention: connections made to SSRFGuard-validated IPs only
- All connections respect per-host timeout
- DNS via public resolvers only
"""
import asyncio
import re
import ssl
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import aiosmtplib
import dns.asyncresolver
import dns.exception
import dns.resolver
import structlog

from app.engines.base import BaseEngine, EngineResult
from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel

logger = structlog.get_logger("mailox.engines.smtp_discovery")

_PUBLIC_NS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
_CTRL_RE = re.compile(r"[^\x20-\x7e\n\r\t]")
_MAX_RESPONSE_LEN = 500


def _sanitize_smtp_response(s: str) -> str:
    if not s:
        return s
    return _CTRL_RE.sub("", s)[:_MAX_RESPONSE_LEN]
_SMTP_PORTS = [587, 25, 465, 2525]
_CONNECT_TIMEOUT = 3.0  # seconds per host/port (short — firewalled ports drop silently)
_HOST_TIMEOUT = 15.0    # total time budget per MX host


def _make_resolver(timeout: float = 5.0, use_system: bool = False) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    if not use_system:
        r.nameservers = _PUBLIC_NS
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


async def _engine_resolver(timeout: float = 5.0):
    """Resolver for discover_mx, always built through ``_make_resolver`` (the
    factory tests patch; same pattern as dns_auth). Keeps the dns_utils
    public-DNS reachability fallback for real resolvers."""
    resolver = _make_resolver(timeout=timeout)
    if isinstance(resolver, dns.asyncresolver.Resolver):
        from app.engines import dns_utils
        if dns_utils._public_dns_ok is None:
            dns_utils._public_dns_ok = await dns_utils._probe_public()
        if not dns_utils._public_dns_ok:
            resolver = _make_resolver(timeout=timeout, use_system=True)
    return resolver




@dataclass
class MXRecord:
    priority: int
    hostname: str
    resolved_ips: list[str] = field(default_factory=list)
    ssrf_blocked: bool = False
    ssrf_reason: Optional[str] = None


@dataclass
class SMTPProbeResult:
    host: str
    port: int
    ip: str
    connected: bool = False
    banner: Optional[str] = None
    ehlo_response: Optional[str] = None
    extensions: dict[str, Any] = field(default_factory=dict)
    starttls_supported: bool = False
    tls_negotiated: bool = False
    tls_info: Optional[dict] = None
    auth_mechanisms: list[str] = field(default_factory=list)
    open_relay_assessment: Optional[str] = None  # "not_tested", "likely_open", "closed", "inconclusive"
    error: Optional[str] = None


# ── MX Discovery ─────────────────────────────────────────────────────────────


async def discover_mx(domain: str, ssrf_guard: SSRFGuard) -> tuple[list[MXRecord], list[Finding]]:
    """Resolve MX records for domain, validate IPs against SSRF guard."""
    resolver = await _engine_resolver()
    findings: list[Finding] = []
    mx_records: list[MXRecord] = []

    try:
        answer = await resolver.resolve(domain, "MX")
        raw = sorted(
            [(int(rdata.preference), str(rdata.exchange).rstrip(".")) for rdata in answer],
            key=lambda x: x[0],
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        raw = []
    except dns.resolver.NoNameservers:
        findings.append(Finding(
            engine="smtp_discovery",
            check_id="SMTP-01",
            title="DNS resolution failed for MX records",
            description=f"Could not resolve MX records for {domain} — no nameservers responded.",
            risk_level=RiskLevel.INFO,
            confidence=0.5,
            evidence=[Evidence(
                type=EvidenceType.ERROR,
                observed_value="DNS no nameservers",
                source=f"DNS MX {domain}",
            )],
            remediation="Verify DNS is functional for this domain.",
            affected_asset=domain,
        ))
        return [], findings
    except dns.exception.Timeout:
        findings.append(Finding(
            engine="smtp_discovery",
            check_id="SMTP-01",
            title="DNS timeout resolving MX records",
            description=f"DNS timed out querying MX records for {domain}.",
            risk_level=RiskLevel.INFO,
            confidence=0.5,
            evidence=[Evidence(type=EvidenceType.TIMEOUT, source=f"DNS MX {domain}")],
            remediation="Verify DNS availability.",
            affected_asset=domain,
        ))
        return [], findings

    if not raw:
        # RFC5321 §5 fallback: if no MX, try A record of domain itself
        try:
            a_answer = await resolver.resolve(domain, "A")
            raw_ip = str(list(a_answer)[0])
            try:
                ssrf_guard.validate_ip(raw_ip)
                fallback_ip = raw_ip
            except SSRFGuardError:
                fallback_ip = "[blocked]"
            findings.append(Finding(
                engine="smtp_discovery",
                check_id="SMTP-02",
                title="No MX records — using implicit MX (A record fallback)",
                description=(
                    f"{domain} has no MX records. Per RFC5321 §5.1, senders may "
                    "fall back to the domain's A record. This is non-standard for "
                    "production email infrastructure."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=f"No MX records; A={fallback_ip}",
                    source=f"DNS MX+A {domain}",
                )],
                remediation="Publish explicit MX records for your mail infrastructure.",
                affected_asset=domain,
            ))
        except Exception:
            findings.append(Finding(
                engine="smtp_discovery",
                check_id="SMTP-03",
                title="No MX records and no A record — domain cannot receive email",
                description=f"{domain} has no MX and no A record. It cannot receive email.",
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.ABSENCE,
                    source=f"DNS MX+A {domain}",
                )],
                remediation="Publish MX records if this domain should receive email.",
                affected_asset=domain,
            ))
        return [], findings

    for priority, hostname in raw:
        mx = MXRecord(priority=priority, hostname=hostname)
        try:
            validated_ips = await ssrf_guard.resolve_and_validate(hostname)
            mx.resolved_ips = validated_ips
        except SSRFGuardError as e:
            mx.ssrf_blocked = True
            mx.ssrf_reason = str(e)
            findings.append(Finding(
                engine="smtp_discovery",
                check_id="SMTP-04",
                title=f"MX host resolves to private/blocked IP: {hostname}",
                description=(
                    f"The MX record {hostname} (priority {priority}) resolves to an IP "
                    f"that is not publicly routable. Reason: {e}"
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=str(e),
                    source=f"DNS A/AAAA {hostname}",
                )],
                remediation="Ensure MX records point to publicly routable mail servers.",
                affected_asset=hostname,
            ))
        mx_records.append(mx)

    return mx_records, findings


# ── SMTP Probe ────────────────────────────────────────────────────────────────


_EGRESS_CONTROL_HOSTS = ("gmail-smtp-in.l.google.com", "mx1.mail.ovh.net")


async def _smtp_egress_open(timeout: float = _CONNECT_TIMEOUT) -> bool:
    """True when this host can open TCP 25 to at least one well-known public MX."""
    for host in _EGRESS_CONTROL_HOSTS:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, 25), timeout)
        except Exception:
            continue
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    return False


async def probe_smtp_host(host: str, ip: str, port: int) -> SMTPProbeResult:
    """
    Connect to host:port (using validated ip), grab banner, EHLO, optionally STARTTLS.
    Does NOT send mail. Does NOT authenticate.

    Security: TCP connects to validated IP (no TOCTOU), but TLS uses the original
    hostname for SNI and certificate validation — servers have certs for their FQDN,
    not for IP addresses.
    """
    result = SMTPProbeResult(host=host, port=ip, ip=ip, connected=False)
    result.host = host
    result.port = port

    use_tls = port == 465  # Implicit TLS (SMTPS)
    smtp = None

    try:
        # aiosmtplib 3.x: validate_certs=False handles self-signed certs (pentest scanner).
        # start_tls=False on non-TLS ports: we do STARTTLS manually after EHLO
        # so we can capture extensions first and control the TLS context.
        # connect() returns SMTPResponse with the 220 banner.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        smtp = aiosmtplib.SMTP(
            hostname=ip,
            port=port,
            use_tls=use_tls,
            start_tls=False,          # manual STARTTLS after EHLO
            tls_context=ctx,
            validate_certs=False,
            timeout=_CONNECT_TIMEOUT,
            source_address=None,
        )
        # Override server_hostname so SNI uses FQDN not IP
        smtp._server_hostname = host  # type: ignore[attr-defined]

        async with asyncio.timeout(_HOST_TIMEOUT):
            greeting = await smtp.connect()
            result.connected = True

            # Banner from 220 greeting response
            if greeting and greeting.message:
                result.banner = _sanitize_smtp_response(greeting.message)

            # For implicit TLS (port 465), TLS is already established at connect time
            if use_tls:
                result.tls_negotiated = True
                ssl_obj = smtp.transport.get_extra_info("ssl_object")  # type: ignore[attr-defined]
                if ssl_obj:
                    cert = ssl_obj.getpeercert()
                    result.tls_info = {
                        "protocol": ssl_obj.version(),
                        "cipher": ssl_obj.cipher(),
                        "subject": cert.get("subject") if cert else None,
                        "san": cert.get("subjectAltName") if cert else None,
                        "not_after": cert.get("notAfter") if cert else None,
                    }

            # EHLO — keyword-only in aiosmtplib 3.x
            ehlo_hostname = "scanner.mailox.internal"
            try:
                ehlo_resp = await smtp.ehlo(hostname=ehlo_hostname)
                result.ehlo_response = _sanitize_smtp_response(ehlo_resp.message)

                # Parse ESMTP extensions from esmtp_extensions dict
                for ext_key, ext_val in smtp.esmtp_extensions.items():
                    ext = ext_key.upper()
                    vals = ext_val.split() if ext_val else []
                    result.extensions[ext] = vals
                    if ext == "AUTH":
                        result.auth_mechanisms = [m.upper() for m in vals]
                    elif ext == "STARTTLS":
                        result.starttls_supported = True

            except Exception:
                try:
                    await smtp.helo(hostname=ehlo_hostname)
                except Exception:
                    pass

            # STARTTLS negotiation on port 25/587
            if result.starttls_supported and not use_tls:
                try:
                    starttls_resp = await smtp.starttls(
                        tls_context=ctx, server_hostname=host, validate_certs=False
                    )
                    result.tls_negotiated = True

                    ssl_obj = smtp.transport.get_extra_info("ssl_object")  # type: ignore[attr-defined]
                    if ssl_obj:
                        cert = ssl_obj.getpeercert()
                        result.tls_info = {
                            "protocol": ssl_obj.version(),
                            "cipher": ssl_obj.cipher(),
                            "subject": cert.get("subject") if cert else None,
                            "san": cert.get("subjectAltName") if cert else None,
                            "not_after": cert.get("notAfter") if cert else None,
                        }

                    # Re-EHLO after STARTTLS
                    try:
                        await smtp.ehlo(hostname=ehlo_hostname)
                        for ext_key, ext_val in smtp.esmtp_extensions.items():
                            ext = ext_key.upper()
                            vals = ext_val.split() if ext_val else []
                            result.extensions[ext] = vals
                            if ext == "AUTH":
                                result.auth_mechanisms = [m.upper() for m in vals]
                    except Exception:
                        pass

                except ssl.SSLCertVerificationError as tls_err:
                    result.tls_negotiated = False
                    err_msg = str(tls_err).lower()
                    if "certificate has expired" in err_msg or "has expired" in err_msg:
                        ssl_error_type = "expired"
                    elif "hostname" in err_msg or "host name" in err_msg or "doesn't match" in err_msg:
                        ssl_error_type = "hostname_mismatch"
                    elif "self signed" in err_msg or "self-signed" in err_msg or "unable to get local issuer" in err_msg:
                        ssl_error_type = "self_signed"
                    else:
                        ssl_error_type = "validation_failed"
                    result.tls_info = {
                        "error": type(tls_err).__name__,
                        "ssl_error_type": ssl_error_type,
                        "ssl_error_msg": str(tls_err)[:300],
                    }
                except Exception as tls_err:
                    result.tls_negotiated = False
                    result.tls_info = {"error": type(tls_err).__name__}

            # Open relay probe
            await _probe_open_relay(smtp, result)

            # VRFY/EXPN user enumeration
            await _probe_vrfy_expn(smtp, result)

    except asyncio.TimeoutError:
        result.error = f"Connection timed out after {_HOST_TIMEOUT}s"
    except (ConnectionRefusedError, OSError) as e:
        result.error = f"Connection refused: {e}"
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
        logger.debug("smtp_probe_error", host=host, port=port, error=str(e))
    finally:
        if smtp is not None:
            try:
                await smtp.quit()
            except Exception:
                pass

    return result


async def _probe_open_relay(smtp: aiosmtplib.SMTP, result: SMTPProbeResult) -> None:
    """
    Non-intrusive open relay probe.
    - Uses controlled FROM and TO addresses (mailox testing domain)
    - Never completes a DATA transaction
    - Issues RSET on any unexpected acceptance
    - Reports "likely_open", "closed", or "inconclusive" only
    """
    # Use a domain that cannot receive real mail (RFC2606 reserved)
    test_from = "probe@mailox-scanner.invalid"
    test_to = "noreply@relay-test.invalid"

    try:
        await smtp.rset()

        resp_from = await smtp.mail(test_from)
        if resp_from.code != 250:
            result.open_relay_assessment = "inconclusive"
            await smtp.rset()
            return

        resp_to = await smtp.rcpt(test_to)
        await smtp.rset()

        code_to = resp_to.code
        if code_to == 250:
            # Server accepted RCPT TO for a foreign domain — likely open relay
            result.open_relay_assessment = "likely_open"
        elif code_to in (550, 551, 552, 553, 554):
            # Server explicitly rejected — not an open relay
            result.open_relay_assessment = "closed"
        else:
            result.open_relay_assessment = "inconclusive"

    except Exception:
        result.open_relay_assessment = "not_tested"
        try:
            await smtp.rset()
        except Exception:
            pass


async def _probe_vrfy_expn(smtp: aiosmtplib.SMTP, result: SMTPProbeResult) -> None:
    """Test VRFY and EXPN commands for user enumeration."""
    for cmd, arg in [("VRFY", "postmaster"), ("EXPN", "postmaster")]:
        try:
            resp = await smtp.execute_command(cmd, arg)
            if resp.code in (250, 251, 252):
                if not hasattr(result, "enum_commands"):
                    result.enum_commands = []
                result.enum_commands.append(f"{cmd}:{resp.code}")
        except Exception:
            pass


# ── Findings from probe results ───────────────────────────────────────────────


_BANNER_VERSION_PATTERNS = [
    (re.compile(r"\bExim\s+([\d.]+)", re.I), "Exim"),
    (re.compile(r"\bPostfix\b", re.I), "Postfix"),
    (re.compile(r"\bSendmail\s+([\d./]+)", re.I), "Sendmail"),
    (re.compile(r"\bMicrosoft\s+ESMTP\s+MAIL\s+Service", re.I), "Microsoft Exchange"),
    (re.compile(r"\bqmail\b", re.I), "qmail"),
    (re.compile(r"\bDovecot\b", re.I), "Dovecot"),
]


def _findings_from_probe(probe: SMTPProbeResult, domain: str) -> list[Finding]:
    findings: list[Finding] = []
    asset = f"{probe.host}:{probe.port}"

    if not probe.connected:
        return []  # Connection failure alone is not a finding — host may not support port

    # SMTP banner — provider fingerprint from banner
    if probe.banner:
        try:
            from app.engines.provider_fingerprint import fingerprint_from_banner
            _banner_provider = fingerprint_from_banner(probe.banner)
            if _banner_provider:
                # No local re-import of Finding/Evidence here: it made them local to the
                # whole function -> UnboundLocalError on every non-matching banner.
                findings.append(Finding(
                    engine="smtp_discovery",
                    check_id="SMTP-ESP-01",
                    title=f"Mail relay provider identified from banner: {_banner_provider.name}",
                    description=f"SMTP banner on {asset} identifies as {_banner_provider.name}.",
                    risk_level=RiskLevel.INFO,
                    confidence=_banner_provider.confidence,
                    evidence=[Evidence(
                        type=EvidenceType.SMTP_RESPONSE,
                        observed_value=probe.banner[:120],
                        source=asset,
                    )],
                    remediation="",
                    affected_asset=asset,
                ))
        except Exception:
            pass

    # SMTP banner — always store in a finding so VulnIntel can read the banner
    if probe.banner:
        mta_product = None
        mta_version = None
        for pattern, product_name in _BANNER_VERSION_PATTERNS:
            m = pattern.search(probe.banner)
            if m:
                mta_product = product_name
                mta_version = m.group(1) if m.lastindex else None
                break

        findings.append(Finding(
            engine="smtp_discovery",
            check_id="SMTP-04",
            title=f"SMTP server identified: {mta_product or 'Unknown MTA'} on {asset}",
            description=(
                f"SMTP banner from {asset}: {probe.banner!r}. "
                + (f"MTA identified as {mta_product} {mta_version or '(version unknown)'}."
                   if mta_product else "MTA software not identified from banner.")
            ),
            risk_level=RiskLevel.INFO,
            confidence=0.95,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=probe.banner,
                source=asset,
                technical_details={
                    "smtp_banner": probe.banner,
                    "mta_product": mta_product,
                    "mta_version": mta_version,
                    "port": probe.port,
                },
            )],
            remediation=(
                "Consider hiding exact version information from SMTP banners "
                "to slow down version-targeted CVE exploitation."
                if mta_version else ""
            ),
            affected_asset=asset,
        ))

    return findings


# ── SMTP Discovery Engine ─────────────────────────────────────────────────────


class SMTPDiscoveryEngine(BaseEngine):
    name = "smtp_discovery"
    default_timeout = 60.0

    def __init__(
        self,
        timeout: Optional[float] = None,
        ports: Optional[list[int]] = None,
        ssrf_guard: Optional[SSRFGuard] = None,
    ) -> None:
        super().__init__(timeout)
        self._ports = ports or _SMTP_PORTS
        self._ssrf_guard = ssrf_guard or SSRFGuard(resolve_timeout=1.5)

    async def _run(self, domain: str) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)

        # MX discovery + SSRF validation
        mx_records, mx_findings = await discover_mx(domain, self._ssrf_guard)
        result.findings.extend(mx_findings)
        result.metadata["mx_records"] = [
            {
                "priority": mx.priority,
                "hostname": mx.hostname,
                "resolved_ips": mx.resolved_ips,
                "ssrf_blocked": mx.ssrf_blocked,
            }
            for mx in mx_records
        ]

        # Probe each reachable MX host (max 3 to bound runtime)
        probes: list[SMTPProbeResult] = []
        for mx in mx_records[:3]:
            if mx.ssrf_blocked or not mx.resolved_ips:
                continue

            ip = mx.resolved_ips[0]  # Use first validated IP
            for port in self._ports:
                probe = await probe_smtp_host(mx.hostname, ip, port)
                probes.append(probe)
                if probe.connected:
                    # Got a response — record and move to next port only if first connect fails
                    break

            # Also check the most important submission port explicitly
            if 587 not in self._ports:
                pass
            elif not any(p.port == 587 and p.host == mx.hostname for p in probes):
                probe587 = await probe_smtp_host(mx.hostname, ip, 587)
                probes.append(probe587)

        result.metadata["probes"] = [
            {
                "host": p.host,
                "port": p.port,
                "ip": p.ip,
                "connected": p.connected,
                "banner": p.banner,
                "starttls": p.starttls_supported,
                "tls_negotiated": p.tls_negotiated,
                "tls_info": p.tls_info,
                "auth_mechanisms": p.auth_mechanisms,
                "open_relay": p.open_relay_assessment,
                "enum_commands": getattr(p, "enum_commands", []),
                "error": p.error,
            }
            for p in probes
        ]

        # Generate findings from probes
        for probe in probes:
            result.findings.extend(_findings_from_probe(probe, domain))

        # No reachable SMTP found at all
        if mx_records and not any(p.connected for p in probes):
            # Many networks (residential ISPs, cloud providers) block outbound port 25.
            # If a well-known public MX is unreachable too, the scanner is the problem.
            if not await _smtp_egress_open():
                result.metadata["smtp_egress_blocked"] = True
                result.findings.append(Finding(
                    engine=self.name,
                    check_id="SMTP-00",
                    title="SMTP checks inconclusive: outbound port 25 blocked from the scanner",
                    description=(
                        f"No SMTP connection to the MX hosts of {domain} succeeded, but a "
                        "reference public mail server was unreachable on port 25 as well. "
                        "The scanner's network blocks outbound SMTP, so nothing can be "
                        "concluded about the target's mail servers."
                    ),
                    risk_level=RiskLevel.INFO,
                    confidence=0.9,
                    evidence=[Evidence(
                        type=EvidenceType.ERROR,
                        observed_value=f"Target and reference MX unreachable: {[p.error for p in probes][:4]}",
                        expected_value=f"TCP connect to {_EGRESS_CONTROL_HOSTS[0]}:25",
                        source=f"SMTP probe {domain}",
                    )],
                    remediation=(
                        "Run the assessment from a network that allows outbound TCP 25 "
                        "(most VPS providers unblock it on request)."
                    ),
                    affected_asset=domain,
                ))
                return result
            result.findings.append(Finding(
                engine=self.name,
                check_id="SMTP-11",
                title="No SMTP ports reachable on any MX host",
                description=(
                    f"MX records were found for {domain} but no SMTP connection "
                    f"succeeded on ports {self._ports}."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.7,
                evidence=[Evidence(
                    type=EvidenceType.ERROR,
                    observed_value=f"All connections failed: {[p.error for p in probes]}",
                    source=f"SMTP probe {domain}",
                )],
                remediation="Verify SMTP ports are reachable from the internet.",
                affected_asset=domain,
            ))

        return result
