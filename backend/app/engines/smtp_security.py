"""
SMTP Security Engine — TLS analysis, auth security, open relay, cert validity, user enumeration.

Receives probe data injected by tasks.py from smtp_discovery results.
Falls back to running own probes if no data injected.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.engines.base import BaseEngine, EngineResult
from app.engines.ssrf_guard import SSRFGuard
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel


def _analyze_probe_dict(probe: dict[str, Any], domain: str) -> list[Finding]:
    """Generate security findings from a probe result dict (from smtp_discovery metadata)."""
    findings: list[Finding] = []
    host = probe.get("host", domain)
    port = probe.get("port", 25)
    asset = f"{host}:{port}"

    if not probe.get("connected"):
        return []

    starttls = probe.get("starttls", False)
    tls_negotiated = probe.get("tls_negotiated", False)
    auth_mechanisms: list[str] = probe.get("auth_mechanisms") or []
    open_relay = probe.get("open_relay")
    tls_info: dict | None = probe.get("tls_info")
    enum_commands: list[str] = probe.get("enum_commands") or []

    # STARTTLS missing on submission ports
    if port in (25, 587) and not starttls:
        findings.append(Finding(
            engine="smtp_security",
            check_id="SMTPS-01",
            title=f"STARTTLS not supported on {asset}",
            description=(
                f"Port {port} on {host} does not advertise STARTTLS. "
                "Email transmitted on this port is unencrypted in transit."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=probe.get("ehlo_response") or "No EHLO response",
                expected_value="EHLO response includes STARTTLS",
                source=asset,
            )],
            remediation="Configure your MTA to offer STARTTLS on port 25 and 587.",
            affected_asset=asset,
        ))

    # STARTTLS advertised but negotiation failed
    if starttls and not tls_negotiated:
        tls_error = (tls_info or {}).get("error", "unknown error")
        findings.append(Finding(
            engine="smtp_security",
            check_id="SMTPS-02",
            title=f"STARTTLS advertised but negotiation failed on {asset}",
            description=(
                f"{host}:{port} advertises STARTTLS but TLS negotiation failed. "
                f"Error: {tls_error}. Clients requiring TLS cannot deliver mail."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.85,
            evidence=[Evidence(
                type=EvidenceType.TLS_CERTIFICATE,
                observed_value=f"TLS error: {tls_error}",
                source=asset,
            )],
            remediation="Fix the TLS configuration on your MTA.",
            affected_asset=asset,
        ))

    # Weak AUTH without TLS
    weak_auth = [m for m in auth_mechanisms if m in ("PLAIN", "LOGIN")]
    if weak_auth and not tls_negotiated and port != 465:
        findings.append(Finding(
            engine="smtp_security",
            check_id="SMTPS-03",
            title=f"Cleartext AUTH mechanisms advertised without TLS on {asset}",
            description=(
                f"{host}:{port} advertises {', '.join(weak_auth)} authentication "
                "without TLS. Credentials submitted over these mechanisms are transmitted in plaintext."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=f"AUTH {' '.join(auth_mechanisms)}",
                expected_value="AUTH mechanisms only advertised after STARTTLS",
                source=asset,
            )],
            remediation=(
                "Configure your MTA to advertise PLAIN/LOGIN only after STARTTLS negotiation."
            ),
            affected_asset=asset,
        ))

    # Suspected open relay
    if open_relay == "likely_open":
        findings.append(Finding(
            engine="smtp_security",
            check_id="SMTPS-04",
            title=f"[SUSPECTED] Open relay: RCPT TO accepted for external domain on {asset}",
            description=(
                f"{host}:{port} accepted RCPT TO for an external RFC2606 address without "
                "authentication. Strongly suggests an open relay. "
                "Confirmation requires a DATA transaction (not performed to avoid sending mail)."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.70,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value="250 OK on RCPT TO <noreply@relay-test.invalid> (unauthenticated)",
                expected_value="550 Relay access denied",
                source=asset,
                technical_details={
                    "probe_method": "MAIL FROM + RCPT TO only (no DATA — non-destructive)",
                    "confirmation_level": "SUSPECTED",
                },
            )],
            remediation=(
                "Restrict RCPT TO to your own domains for unauthenticated connections. "
                "Require authentication before relaying to external domains."
            ),
            affected_asset=asset,
            business_impact=(
                "If confirmed, open relays enable spam and phishing from your IP, "
                "causing blacklisting and reputational damage."
            ),
        ))

    # TLS certificate expiry (from successful TLS negotiation with cert data)
    # ssl_error_type == "expired" takes precedence over not_after parsing to avoid duplicates
    _already_flagged_expired = False
    if tls_info and tls_info.get("not_after") and not (tls_info or {}).get("ssl_error_type") == "expired":
        try:
            from datetime import datetime as _dt
            not_after_str: str = tls_info["not_after"]
            # getpeercert() returns "MMM DD HH:MM:SS YYYY TZ", e.g. "Jan  1 00:00:00 2024 GMT"
            not_after = _dt.strptime(not_after_str.strip(), "%b %d %H:%M:%S %Y %Z")
            now_naive = _dt.now(timezone.utc).replace(tzinfo=None)
            days_left = (not_after - now_naive).days
            if days_left < 0:
                _already_flagged_expired = True
                findings.append(Finding(
                    engine="smtp_security",
                    check_id="SMTPS-05",
                    title=f"TLS certificate expired on {asset}",
                    description=f"TLS certificate on {asset} expired {abs(days_left)} days ago.",
                    risk_level=RiskLevel.CRITICAL,
                    confidence=1.0,
                    evidence=[Evidence(
                        type=EvidenceType.TLS_CERTIFICATE,
                        observed_value=f"notAfter: {not_after_str} (expired {abs(days_left)}d ago)",
                        source=asset,
                        technical_details=tls_info,
                    )],
                    remediation="Renew the TLS certificate immediately.",
                    affected_asset=asset,
                ))
            elif days_left < 30:
                findings.append(Finding(
                    engine="smtp_security",
                    check_id="SMTPS-11",  # distinct from SMTPS-06 (hostname mismatch)
                    title=f"TLS certificate expiring soon on {asset} ({days_left}d)",
                    description=f"TLS certificate on {asset} expires in {days_left} days.",
                    risk_level=RiskLevel.MEDIUM if days_left > 7 else RiskLevel.HIGH,
                    confidence=1.0,
                    evidence=[Evidence(
                        type=EvidenceType.TLS_CERTIFICATE,
                        observed_value=f"notAfter: {not_after_str} ({days_left}d remaining)",
                        source=asset,
                        technical_details=tls_info,
                    )],
                    remediation="Renew the TLS certificate before expiry.",
                    affected_asset=asset,
                ))
        except Exception:
            pass

    # TLS certificate validation errors (ssl.SSLCertVerificationError during negotiation)
    if tls_info and tls_info.get("ssl_error_type"):
        ssl_err_type: str = tls_info["ssl_error_type"]
        ssl_err_msg: str = tls_info.get("ssl_error_msg", "")
        if ssl_err_type == "expired" and not _already_flagged_expired:
            findings.append(Finding(
                engine="smtp_security",
                check_id="SMTPS-05",
                title=f"TLS certificate expired on {asset}",
                description=(
                    f"TLS negotiation with {asset} failed due to an expired certificate. "
                    "Mail clients enforcing TLS will reject this server."
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.TLS_CERTIFICATE,
                    observed_value=f"SSLCertVerificationError: {ssl_err_msg[:120]}",
                    source=asset,
                    technical_details=tls_info,
                )],
                remediation="Renew the TLS certificate immediately.",
                affected_asset=asset,
            ))
        elif ssl_err_type == "hostname_mismatch":
            findings.append(Finding(
                engine="smtp_security",
                check_id="SMTPS-06",
                title=f"TLS certificate hostname mismatch on {asset}",
                description=(
                    f"The certificate presented by {asset} does not match its hostname. "
                    "Strict TLS clients will reject the connection."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.TLS_CERTIFICATE,
                    observed_value=f"SSLCertVerificationError: {ssl_err_msg[:120]}",
                    source=asset,
                    technical_details=tls_info,
                )],
                remediation=(
                    "Ensure the certificate SANs include all hostnames used for this MX record. "
                    "Reissue the certificate with the correct subject alternative names."
                ),
                affected_asset=asset,
            ))
        elif ssl_err_type in ("self_signed", "validation_failed"):
            label = "self-signed" if ssl_err_type == "self_signed" else "untrusted/invalid"
            findings.append(Finding(
                engine="smtp_security",
                check_id="SMTPS-09",
                title=f"TLS certificate {label} on {asset}",
                description=(
                    f"The TLS certificate on {asset} is {label} and not trusted by standard "
                    "certificate authorities. Mail clients enforcing verified TLS will refuse delivery."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.TLS_CERTIFICATE,
                    observed_value=f"SSLCertVerificationError ({ssl_err_type}): {ssl_err_msg[:120]}",
                    source=asset,
                    technical_details=tls_info,
                )],
                remediation=(
                    "Replace the self-signed certificate with one issued by a trusted CA "
                    "(e.g., Let's Encrypt). Ensure the full chain is served."
                ),
                affected_asset=asset,
            ))

    # TLS cipher strength (if negotiated)
    if tls_negotiated and tls_info and tls_info.get("cipher"):
        cipher = tls_info["cipher"]
        cipher_name = cipher[0] if isinstance(cipher, (list, tuple)) else str(cipher)
        protocol = tls_info.get("protocol", "")
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(Finding(
                engine="smtp_security",
                check_id="SMTPS-07",
                title=f"Deprecated TLS version in use on {asset}: {protocol}",
                description=(
                    f"{host}:{port} negotiated {protocol} which is deprecated and insecure. "
                    "Modern mail servers should use TLS 1.2 or 1.3."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.TLS_CERTIFICATE,
                    observed_value=f"Protocol: {protocol}, Cipher: {cipher_name}",
                    expected_value="TLSv1.2 or TLSv1.3",
                    source=asset,
                    technical_details=tls_info,
                )],
                remediation="Disable TLS 1.0 and 1.1. Configure minimum TLSv1.2.",
                affected_asset=asset,
            ))

        # Weak cipher suite detection — based on the actually negotiated cipher
        # ssl.SSLSocket.cipher() returns (name, protocol, bits) tuple
        _WEAK_CIPHER_PATTERNS = (
            "RC4", "RC2", "DES", "3DES", "NULL", "EXPORT", "anon", "ADH", "AECDH", "MD5"
        )
        cipher_upper = cipher_name.upper()
        matched_weak = next(
            (p for p in _WEAK_CIPHER_PATTERNS if p.upper() in cipher_upper), None
        )
        if matched_weak:
            findings.append(Finding(
                engine="smtp_security",
                check_id="SMTPS-10",
                title=f"Weak cipher suite negotiated on {asset}: {cipher_name}",
                description=(
                    f"{host}:{port} negotiated cipher suite '{cipher_name}' which is "
                    f"cryptographically weak (matches pattern: {matched_weak}). "
                    "Weak ciphers expose email traffic to decryption or forgery."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.TLS_CERTIFICATE,
                    observed_value=f"Cipher: {cipher_name}, Protocol: {protocol}",
                    expected_value="ECDHE-RSA-AES256-GCM-SHA384 or equivalent forward-secret cipher",
                    source=asset,
                    technical_details=tls_info,
                )],
                remediation=(
                    "Remove weak cipher suites from your MTA TLS configuration. "
                    "Prefer ECDHE+AESGCM, ECDHE+CHACHA20, DHE+AESGCM cipher suites. "
                    "Postfix: set `smtp_tls_ciphers = high` and "
                    "`smtp_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, 3DES, RC4, MD5`."
                ),
                affected_asset=asset,
            ))

    # VRFY/EXPN user enumeration
    if enum_commands:
        cmds_str = ", ".join(enum_commands)
        findings.append(Finding(
            engine="smtp_security",
            check_id="SMTPS-08",
            title=f"User enumeration via VRFY/EXPN enabled on {asset}",
            description=(
                f"{host}:{port} responded to VRFY/EXPN commands ({cmds_str}). "
                "These commands allow an attacker to enumerate valid email addresses without authentication."
            ),
            risk_level=RiskLevel.MEDIUM,
            confidence=0.9,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=f"Commands accepted: {cmds_str}",
                expected_value="502 Command not implemented / 550 Access denied",
                source=asset,
            )],
            remediation=(
                "Disable VRFY and EXPN in your MTA config.\n"
                "Postfix: `disable_vrfy_command = yes`\n"
                "Exim: `no_vrfy` in ACL config"
            ),
            affected_asset=asset,
            business_impact=(
                "Attackers enumerate valid addresses for targeted phishing or credential stuffing."
            ),
        ))

    return findings


class SMTPSecurityEngine(BaseEngine):
    name = "smtp_security"
    default_timeout = 90.0

    async def _run(self, domain: str) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)

        # Probe dicts injected from tasks.py via smtp_discovery metadata
        probe_data: list[dict] = getattr(self, "_smtp_probe_data", None) or []

        if not probe_data:
            # Fallback: run own probes (slower path, used when injected data unavailable)
            try:
                from app.engines.smtp_discovery import discover_mx, probe_smtp_host, _SMTP_PORTS
                ssrf_guard = SSRFGuard(resolve_timeout=1.5)
                mx_records, _ = await discover_mx(domain, ssrf_guard)
                raw_probes = []
                for mx in mx_records[:3]:
                    if mx.ssrf_blocked or not mx.resolved_ips:
                        continue
                    ip = mx.resolved_ips[0]
                    for port in _SMTP_PORTS:
                        probe = await probe_smtp_host(mx.hostname, ip, port)
                        if probe.connected:
                            raw_probes.append({
                                "host": probe.host,
                                "port": probe.port,
                                "connected": probe.connected,
                                "starttls": probe.starttls_supported,
                                "tls_negotiated": probe.tls_negotiated,
                                "tls_info": probe.tls_info,
                                "auth_mechanisms": probe.auth_mechanisms,
                                "open_relay": probe.open_relay_assessment,
                                "enum_commands": getattr(probe, "enum_commands", []),
                            })
                            break
                probe_data = raw_probes
            except Exception as exc:
                result.error = f"Failed to gather SMTP probes: {exc}"
                return result

        result.metadata["probe_count"] = len(probe_data)

        for probe in probe_data:
            result.findings.extend(_analyze_probe_dict(probe, domain))

        return result
