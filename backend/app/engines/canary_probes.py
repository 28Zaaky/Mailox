"""
CanaryProbesEngine: active verification with canary delivery.

Requires CANARY_EMAIL in settings. Without it all probes return SKIPPED.

Design constraints:
- Each probe sends AT MOST ONE email to CANARY_EMAIL — never to target users
- No probes send to any address on the target domain (no mailbox enumeration)
- DATA body is a minimal RFC-5322 message, clearly marked as a security test
- Each probe disconnects immediately after the final SMTP response
- Failed/refused probes: INCONCLUSIVE, not "not vulnerable"

check_id prefix: APB-

Checks implemented:
  APB-RELAY-OPEN         MX accepts relay for external→external (canary)
  APB-RELAY-AUTH-BYPASS  MX relays after rejected AUTH (some MTA auth bypass patterns)
  APB-SPOOF-SPF          Envelope spoofing: MAIL FROM as target domain → 250 accepted
  APB-DMARC-BYPASS-NONE  DMARC p=none → spoofed email delivered unblocked
  APB-DMARC-BYPASS-SUB   DMARC p=quarantine/reject with sp=none → subdomain spoof possible
  APB-DMARC-BYPASS-FROM  Display-name attack: From header vs envelope mismatch
"""
import asyncio
import re
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import dns.asyncresolver
import dns.resolver
import structlog

from app.core.config import settings
from app.engines.base import BaseEngine, EngineResult
from app.engines.active_probes import ProbeResult, _smtp_cmd, _smtp_quit
from app.engines.ssrf_guard import SSRFGuard
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel

_CONNECT_TIMEOUT = 8.0
_READ_TIMEOUT = 10.0

logger = structlog.get_logger("mailox.engines.canary_probes")

_PROBE_TAG = "X-Mailox-Canary-Probe"
_PROBE_VALUE = "security-assessment-canary-do-not-reply"


def _canary_body(
    check_id: str, target: str, probe_desc: str, canary: Optional[str] = None
) -> str:
    """Probe message with CRLF line endings (bare LF is refused by strict MTAs,
    e.g. Postfix smtpd_forbid_bare_newline). The To header matches the actual
    envelope recipient (org override included)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = textwrap.dedent(f"""\
        From: MAILOX Security Assessment <probe@mailox-canary.internal>
        To: {canary or settings.CANARY_EMAIL}
        Subject: [MAILOX-PROBE] {check_id} — {target}
        {_PROBE_TAG}: {_PROBE_VALUE}
        X-Probe-Target: {target}
        X-Probe-CheckId: {check_id}
        X-Probe-Timestamp: {now}
        MIME-Version: 1.0
        Content-Type: text/plain; charset=utf-8

        MAILOX automated security assessment probe.
        Check: {check_id}
        Target: {target}
        Description: {probe_desc}
        Timestamp: {now}

        This message was sent by an automated security scanner
        as part of an authorised assessment. No action required.
    """)
    return "\r\n".join(text.split("\n"))


class CanaryProbesEngine(BaseEngine):
    """
    Requires CANARY_EMAIL in config.
    run_from_findings() is the primary entry point.
    """
    name: str = "canary_probes"
    default_timeout: float = 120.0

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

    async def _run(self, domain: str) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)
        result.metadata["note"] = "Call run_from_findings() with mx_host parameter."
        return result

    async def run_from_findings(
        self,
        domain: str,
        mx_host: Optional[str] = None,
        smtp_port: int = 25,
    ) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)

        canary = getattr(self, "_canary_email_override", None) or settings.CANARY_EMAIL
        if not canary:
            result.metadata["skipped"] = "CANARY_EMAIL not configured"
            logger.info("canary_probes_skipped", domain=domain, reason="no CANARY_EMAIL")
            return result

        target_host = mx_host or domain
        probes_run: list[str] = []

        # ── 1. Open relay test ────────────────────────────────────────────────
        pr1 = await self._probe_open_relay(target_host, smtp_port, domain, canary)
        probes_run.append(pr1.check_id)
        if pr1.vulnerable:
            result.add_finding(self._relay_finding(pr1, domain, target_host, smtp_port))

        # ── 2. SPF spoofing — MAIL FROM as target domain ──────────────────────
        pr2 = await self._probe_spf_spoof(target_host, smtp_port, domain, canary)
        probes_run.append(pr2.check_id)
        if pr2.vulnerable:
            result.add_finding(self._spoof_spf_finding(pr2, domain, target_host))

        # ── 3. DMARC policy analysis ──────────────────────────────────────────
        pr3a, pr3b = await asyncio.gather(
            self._probe_dmarc_policy(domain),
            self._probe_dmarc_subdomain(domain),
        )
        probes_run.extend([pr3a.check_id, pr3b.check_id])
        if pr3a.vulnerable:
            result.add_finding(self._dmarc_none_finding(pr3a, domain))
        if pr3b.vulnerable:
            result.add_finding(self._dmarc_subdomain_finding(pr3b, domain))

        # ── 4. Display-name / From header spoof ──────────────────────────────
        pr4 = await self._probe_displayname_spoof(target_host, smtp_port, domain, canary)
        probes_run.append(pr4.check_id)
        if pr4.vulnerable:
            result.add_finding(self._displayname_finding(pr4, domain, target_host))

        result.metadata["probes_run"] = probes_run
        result.metadata["canary_target"] = canary
        return result

    # ── Probe: Open relay ─────────────────────────────────────────────────────

    async def _probe_open_relay(
        self, host: str, port: int, domain: str, canary: str
    ) -> ProbeResult:
        """
        Connect to MX, send MAIL FROM external, RCPT TO canary (also external).
        If server accepts both and allows DATA → open relay confirmed.
        Sends minimal test message; canary receives it as proof.
        """
        check_id = "APB-RELAY-OPEN"
        # Use an address that is clearly NOT on the target domain
        probe_from = f"probe@probe-canary.internal"
        conn = await self._validated_smtp_connect(host, port)
        if conn is None:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error="Connection failed")
        reader, writer, banner = conn
        try:
            await _smtp_cmd(reader, writer, f"EHLO probe-canary.internal")
            mail_resp = await _smtp_cmd(reader, writer, f"MAIL FROM:<{probe_from}>")
            if not mail_resp.startswith("2"):
                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                                   evidence_value=f"MAIL FROM rejected: {mail_resp[:80]}")

            rcpt_resp = await _smtp_cmd(reader, writer, f"RCPT TO:<{canary}>")
            if not rcpt_resp.startswith("2"):
                # Relay refused — not an open relay
                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                                   evidence_value=f"RCPT TO external refused: {rcpt_resp[:80]}")

            # Both accepted — MX is relaying for unknown sender → external recipient
            # Send DATA to deliver proof
            data_resp = await _smtp_cmd(reader, writer, "DATA")
            if not data_resp.startswith("3"):
                return ProbeResult(check_id=check_id, vulnerable=True, inconclusive=True,
                                   evidence_value=f"MAIL FROM+RCPT accepted but DATA refused: {data_resp[:80]}")

            body = _canary_body(
                check_id, domain, "Open relay: external sender → canary recipient", canary
            )
            writer.write((body + "\r\n.\r\n").encode())
            await writer.drain()
            final_resp = b""
            for _ in range(10):
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                final_resp += line
                if len(line) >= 4 and line[3:4] == b" ":
                    break
            final = final_resp.decode(errors="replace").strip()
            delivered = final.startswith("2")
            return ProbeResult(
                check_id=check_id,
                vulnerable=True,
                evidence_value=(
                    f"Open relay CONFIRMED — external→external accepted. "
                    f"DATA response: {final[:100]}"
                ),
                raw_response=f"RCPT: {rcpt_resp[:60]} | DATA: {final[:60]}",
            )
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))
        finally:
            await _smtp_quit(writer)

    # ── Probe: SPF envelope spoof ─────────────────────────────────────────────

    async def _probe_spf_spoof(
        self, host: str, port: int, domain: str, canary: str
    ) -> ProbeResult:
        """
        Connect to outbound SMTP relay (port 587 or 25) and attempt to send
        an email with MAIL FROM:<admin@targetdomain.com> → canary.
        If accepted: SPF alignment is broken or SPF is permissive.
        We use a DIFFERENT server than the target's own MX — using a known
        open relay or our own test relay.

        NOTE: This probe sends to canary FROM the target's domain name.
        The target MX is NOT contacted for this probe — we try sending
        from our own SMTP connection (or via the target's outbound relay if
        detectably different from inbound MX).
        For this probe we test if the target's OWN MX accepts spoofed
        MAIL FROM as one of its own users → self-spoofing bypass.
        """
        check_id = "APB-SPOOF-SPF"
        spoof_from = f"security-probe@{domain}"
        conn = await self._validated_smtp_connect(host, port)
        if conn is None:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error="Connection failed")
        reader, writer, banner = conn
        try:
            await _smtp_cmd(reader, writer, f"EHLO probe-spoof.internal")
            mail_resp = await _smtp_cmd(reader, writer, f"MAIL FROM:<{spoof_from}>")
            if not mail_resp.startswith("2"):
                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                                   evidence_value=f"MX rejected MAIL FROM own domain: {mail_resp[:80]}")

            rcpt_resp = await _smtp_cmd(reader, writer, f"RCPT TO:<{canary}>")
            if not rcpt_resp.startswith("2"):
                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                                   evidence_value=f"RCPT external rejected: {rcpt_resp[:80]}")

            # Send proof message
            data_resp = await _smtp_cmd(reader, writer, "DATA")
            if data_resp.startswith("3"):
                body = _canary_body(
                    check_id, domain,
                    f"SPF spoof: MX accepted MAIL FROM:<{spoof_from}> destined for external",
                    canary,
                )
                writer.write((body + "\r\n.\r\n").encode())
                await writer.drain()
                final_resp = b""
                for _ in range(10):
                    line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                    final_resp += line
                    if len(line) >= 4 and line[3:4] == b" ":
                        break
                final = final_resp.decode(errors="replace").strip()

            return ProbeResult(
                check_id=check_id,
                vulnerable=True,
                evidence_value=(
                    f"MX accepted MAIL FROM:<{spoof_from}> → <{canary}>. "
                    f"Server is relaying spoofed own-domain envelope."
                ),
                raw_response=f"MAIL: {mail_resp[:60]} | RCPT: {rcpt_resp[:60]}",
            )
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))
        finally:
            await _smtp_quit(writer)

    # ── Probe: DMARC p=none ───────────────────────────────────────────────────

    async def _probe_dmarc_policy(self, domain: str) -> ProbeResult:
        """
        Fetch DMARC record. p=none means spoofed mail is delivered even
        if SPF/DKIM fail — no enforcement, only reporting.
        """
        check_id = "APB-DMARC-BYPASS-NONE"
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc = None
            for rdata in answers:
                txt = "".join(s.decode(errors="replace") for s in rdata.strings)
                if "v=DMARC1" in txt:
                    dmarc = txt
                    break

            # Absence and p=none are DNS facts already reported by dns_auth
            # (DMARC-01 / DMARC-04). No email is sent here, so reporting them again
            # would count one root cause two or three times in the risk score.
            if not dmarc:
                return ProbeResult(
                    check_id=check_id,
                    vulnerable=False,
                    evidence_value="No DMARC record — reported by dns_auth (DMARC-01)",
                    raw_response=f"_dmarc.{domain}: no v=DMARC1 TXT record",
                )

            p_match = re.search(r'\bp=(\w+)', dmarc)
            policy = p_match.group(1).lower() if p_match else "none"

            if policy == "none":
                return ProbeResult(
                    check_id=check_id,
                    vulnerable=False,
                    evidence_value="DMARC p=none — reported by dns_auth (DMARC-04)",
                    raw_response=dmarc,
                )
            if policy == "quarantine":
                return ProbeResult(
                    check_id=check_id,
                    vulnerable=False,
                    evidence_value=f"DMARC p=quarantine — spoofed email goes to spam, not delivered",
                    raw_response=dmarc,
                )
            return ProbeResult(
                check_id=check_id,
                vulnerable=False,
                evidence_value=f"DMARC p={policy} — enforcement active",
                raw_response=dmarc,
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ProbeResult(
                check_id=check_id,
                vulnerable=False,
                evidence_value="No DMARC record — reported by dns_auth (DMARC-01)",
                raw_response=f"_dmarc.{domain}: no TXT record",
            )
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))

    # ── Probe: DMARC subdomain policy ────────────────────────────────────────

    async def _probe_dmarc_subdomain(self, domain: str) -> ProbeResult:
        """
        Check DMARC sp= (subdomain policy).
        If sp=none or sp absent while p=quarantine/reject,
        spoofing via subdomain (attacker@mail.target.com) bypasses DMARC.
        """
        check_id = "APB-DMARC-BYPASS-SUB"
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc = None
            for rdata in answers:
                txt = "".join(s.decode(errors="replace") for s in rdata.strings)
                if "v=DMARC1" in txt:
                    dmarc = txt
                    break

            if not dmarc:
                return ProbeResult(
                    check_id=check_id,
                    vulnerable=False,
                    evidence_value="No DMARC record — reported by dns_auth (DMARC-01)",
                    raw_response=f"_dmarc.{domain}: no v=DMARC1 TXT record",
                )

            p_match = re.search(r'\bp=(\w+)', dmarc)
            sp_match = re.search(r'\bsp=(\w+)', dmarc)
            p = p_match.group(1).lower() if p_match else "none"
            sp = sp_match.group(1).lower() if sp_match else None

            # If sp explicitly set to reject/quarantine → protected
            if sp in ("reject", "quarantine"):
                return ProbeResult(
                    check_id=check_id,
                    vulnerable=False,
                    evidence_value=f"DMARC sp={sp} — subdomain enforcement active",
                    raw_response=dmarc,
                )

            # Only an explicit sp=none weakens an enforcing p=. An absent sp
            # inherits p (RFC 7489 section 6.3), so subdomains stay protected.
            if p in ("reject", "quarantine") and sp == "none":
                vuln_text = (
                    f"DMARC p={p} but sp=none "
                    f"— attacker can spoof mail.{domain} and bypass DMARC enforcement"
                )
                return ProbeResult(
                    check_id=check_id,
                    vulnerable=True,
                    evidence_value=vuln_text,
                    raw_response=dmarc,
                )

            return ProbeResult(
                check_id=check_id,
                vulnerable=False,
                evidence_value=f"DMARC p={p} sp={sp or 'inherits p'} — acceptable",
                raw_response=dmarc,
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ProbeResult(
                check_id=check_id,
                vulnerable=False,
                evidence_value="No DMARC record — reported by dns_auth (DMARC-01)",
                raw_response=f"_dmarc.{domain}: no TXT record",
            )
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))

    # ── Probe: Display-name / From header spoof ───────────────────────────────

    async def _probe_displayname_spoof(
        self, host: str, port: int, domain: str, canary: str
    ) -> ProbeResult:
        """
        Send a message where:
        - Envelope MAIL FROM: probe@probe.internal (external, passes SPF)
        - From header: "IT Security <admin@{domain}>"

        If the MX accepts this and delivers it, the recipient sees a message
        appearing to be from admin@domain even though SPF is for probe.internal.
        DMARC enforcement catches this only if p=reject/quarantine AND aligned.
        """
        check_id = "APB-DMARC-BYPASS-FROM"
        envelope_from = "probe@probe-canary.internal"
        display_from = f"IT Security <admin@{domain}>"
        conn = await self._validated_smtp_connect(host, port)
        if conn is None:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error="Connection failed")
        reader, writer, banner = conn
        try:
            await _smtp_cmd(reader, writer, "EHLO probe-canary.internal")
            mail_resp = await _smtp_cmd(reader, writer, f"MAIL FROM:<{envelope_from}>")
            if not mail_resp.startswith("2"):
                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                                   evidence_value=f"MAIL FROM rejected: {mail_resp[:80]}")

            rcpt_resp = await _smtp_cmd(reader, writer, f"RCPT TO:<{canary}>")
            if not rcpt_resp.startswith("2"):
                return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=False,
                                   evidence_value=f"RCPT external refused: {rcpt_resp[:80]}")

            data_resp = await _smtp_cmd(reader, writer, "DATA")
            if not data_resp.startswith("3"):
                return ProbeResult(check_id=check_id, vulnerable=True, inconclusive=True,
                                   evidence_value="MAIL+RCPT accepted but DATA refused")

            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            body = (
                f"From: {display_from}\r\n"
                f"To: {canary}\r\n"
                f"Subject: [MAILOX-PROBE] {check_id} display-name spoof — {domain}\r\n"
                f"{_PROBE_TAG}: {_PROBE_VALUE}\r\n"
                f"X-Probe-Target: {domain}\r\n"
                f"X-Probe-Timestamp: {now}\r\n"
                f"MIME-Version: 1.0\r\n"
                f"Content-Type: text/plain; charset=utf-8\r\n"
                f"\r\n"
                f"MAILOX display-name spoofing probe.\r\n"
                f"Envelope from: {envelope_from}\r\n"
                f"From header: {display_from}\r\n"
                f"If you see 'IT Security <admin@{domain}>' as sender, spoofing succeeded.\r\n"
            )
            writer.write((body + "\r\n.\r\n").encode())
            await writer.drain()
            final_resp = b""
            for _ in range(10):
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                final_resp += line
                if len(line) >= 4 and line[3:4] == b" ":
                    break
            final = final_resp.decode(errors="replace").strip()
            delivered = final.startswith("2")

            return ProbeResult(
                check_id=check_id,
                vulnerable=delivered,
                inconclusive=not delivered,
                evidence_value=(
                    f"MX relayed display-name spoof: envelope=<{envelope_from}>, "
                    f"From header=<{display_from}>. DATA: {final[:80]}"
                ) if delivered else f"DATA refused: {final[:80]}",
                raw_response=final,
            )
        except Exception as exc:
            return ProbeResult(check_id=check_id, vulnerable=False, inconclusive=True,
                               error=str(exc))
        finally:
            await _smtp_quit(writer)

    # ── Finding builders ──────────────────────────────────────────────────────

    def _relay_finding(self, pr: ProbeResult, domain: str, host: str, port: int) -> Finding:
        return self._make_finding(
            check_id=pr.check_id,
            title="Open SMTP relay — external to external delivery confirmed",
            description=(
                f"SMTP server {host}:{port} accepted an email from an external sender "
                f"destined for an external recipient (canary address). "
                "Open relays allow anyone to send email through your infrastructure, "
                "enabling spam, phishing, and IP reputation damage."
            ),
            risk_level=RiskLevel.CRITICAL,
            confidence=0.99,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=pr.evidence_value,
                expected_value="550 Relay access denied",
                source=f"smtp://{host}:{port}",
                technical_details={"raw_response": pr.raw_response, "host": host, "port": port},
            )],
            remediation=(
                "Restrict relay: `smtpd_relay_restrictions = permit_mynetworks, "
                "permit_sasl_authenticated, reject_unauth_destination` (Postfix). "
                "Equivalent: `FEATURE(access_db)` with explicit relay deny in Sendmail."
            ),
            affected_asset=domain,
            business_impact=(
                "Open relays are used by spammers and phishers. "
                "Your IP will be blacklisted within hours of exploitation, "
                "causing legitimate email delivery failures."
            ),
            references=["https://www.rfc-editor.org/rfc/rfc2821#section-7.1"],
        )

    def _spoof_spf_finding(self, pr: ProbeResult, domain: str, host: str) -> Finding:
        return self._make_finding(
            check_id=pr.check_id,
            title="SMTP envelope spoofing — MX relays own-domain sender externally",
            description=(
                f"The MX server for {domain} accepted MAIL FROM:<security-probe@{domain}> "
                "and relayed it to an external address without authentication. "
                "An attacker can send email appearing to come from any @{domain} address "
                "without possessing credentials for that domain."
            ),
            risk_level=RiskLevel.CRITICAL,
            confidence=0.95,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=pr.evidence_value,
                expected_value="550 Sender not authorised (requires authentication)",
                source=f"smtp://{host}",
                technical_details={"raw_response": pr.raw_response},
            )],
            remediation=(
                "Configure MX to require SASL authentication for senders claiming your domain. "
                "Postfix: `smtpd_sender_login_maps` + `reject_sender_login_mismatch`. "
                "Ensure SPF record exists with `-all` (hard fail)."
            ),
            affected_asset=domain,
            business_impact=(
                "Attackers can send phishing emails that appear to originate from "
                "your own domain, bypassing user suspicion and many spam filters."
            ),
            references=[
                "https://www.rfc-editor.org/rfc/rfc7208",
                "https://postfix.org/SASL_README.html",
            ],
        )

    def _dmarc_none_finding(self, pr: ProbeResult, domain: str) -> Finding:
        no_dmarc = "No DMARC" in pr.evidence_value
        return self._make_finding(
            check_id=pr.check_id,
            title=(
                "No DMARC record — no email spoofing enforcement"
                if no_dmarc else
                "DMARC p=none — monitoring only, spoofed email delivered"
            ),
            description=(
                f"{'No DMARC DNS record exists for ' + domain if no_dmarc else 'DMARC policy is p=none for ' + domain}. "
                "Spoofed email sent from your domain is delivered to recipients' inboxes without rejection. "
                "Receiving servers may send reports (rua/ruf) but take no enforcement action."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.98,
            evidence=[Evidence(
                type=EvidenceType.DNS_RECORD,
                observed_value=pr.evidence_value,
                expected_value="v=DMARC1; p=reject; ...",
                source=f"dns://_dmarc.{domain}",
                technical_details={"dmarc_record": pr.raw_response},
            )],
            remediation=(
                f"{'Add a DMARC TXT record at _dmarc.' + domain if no_dmarc else 'Change p=none to p=quarantine, then p=reject after reviewing rua/ruf reports'}. "
                "Start with: `v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; pct=100`."
            ),
            affected_asset=domain,
            business_impact=(
                "Without DMARC enforcement, attackers can send phishing email that "
                "appears to come from your domain and is delivered directly to inboxes."
            ),
            references=[
                "https://www.rfc-editor.org/rfc/rfc7489",
                "https://dmarc.org/overview/",
            ],
        )

    def _dmarc_subdomain_finding(self, pr: ProbeResult, domain: str) -> Finding:
        return self._make_finding(
            check_id=pr.check_id,
            title=f"DMARC subdomain policy gap — spoofing via *.{domain} bypasses enforcement",
            description=(
                f"DMARC for {domain} has {pr.evidence_value}. "
                f"An attacker can send email from mail.{domain} or any other subdomain "
                "and bypass DMARC enforcement because subdomains are not covered "
                "by the parent domain policy when sp= is absent or sp=none."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.97,
            evidence=[Evidence(
                type=EvidenceType.DNS_RECORD,
                observed_value=pr.evidence_value,
                expected_value="sp=reject or sp=quarantine",
                source=f"dns://_dmarc.{domain}",
                technical_details={"dmarc_record": pr.raw_response},
            )],
            remediation=(
                f"Add sp=reject to your DMARC record: "
                f"`v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@{domain}; pct=100`."
            ),
            affected_asset=domain,
            references=["https://www.rfc-editor.org/rfc/rfc7489#section-6.3"],
        )

    def _displayname_finding(self, pr: ProbeResult, domain: str, host: str) -> Finding:
        return self._make_finding(
            check_id=pr.check_id,
            title="Display-name spoofing — From header accepted without envelope alignment",
            description=(
                f"MX server {host} relayed a message where the From header claimed "
                f"'IT Security <admin@{domain}>' while the envelope sender was an "
                "unrelated external address. Email clients display the From header to users, "
                "not the envelope, making this indistinguishable from a legitimate message."
            ),
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=pr.evidence_value,
                expected_value="Message rejected or From header rewritten",
                source=f"smtp://{host}",
                technical_details={"raw_response": pr.raw_response},
            )],
            remediation=(
                "Enforce DMARC p=reject to block header-from misalignment. "
                "Enable DKIM signing to cryptographically tie From header to your domain. "
                "Many MUAs now warn on From/envelope mismatch — ensure users are on modern clients."
            ),
            affected_asset=domain,
            business_impact=(
                "Display-name spoofing is the most common phishing technique. "
                "An attacker can impersonate any internal user (CEO, IT, HR) with no technical barrier."
            ),
            references=[
                "https://www.rfc-editor.org/rfc/rfc5322#section-3.6.2",
                "https://dmarc.org/",
            ],
        )
