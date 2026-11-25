"""
DNS Authentication Engine — SPF, DKIM, DMARC analysis.

Design notes:
- SPF: recursive include flattening (read-only), 10-lookup limit per RFC7208
- DKIM: best-effort selector discovery; absence ≠ DKIM disabled (undiscoverable selectors)
- DMARC: p=none is not auto-CRITICAL — context matters (new deployment vs mature domain)
- All DNS operations via public resolvers, no internal DNS
- Timeouts per record type to bound total engine runtime
"""
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import dns.asyncresolver
import dns.exception
import dns.resolver
import structlog

from app.core.config import SCANNER_USER_AGENT
from app.engines.base import BaseEngine, EngineResult
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel


def _summary_title(prefix: str, names: list[str]) -> str:
    """'<prefix>: A' / '<prefix>: A, B' / '<prefix>: A, B (+3 more)'."""
    shown = ", ".join(names[:2])
    extra = len(names) - 2
    return f"{prefix}: {shown}" + (f" (+{extra} more)" if extra > 0 else "")


logger = structlog.get_logger("mailox.engines.dns_auth")

_PUBLIC_NS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# Selectors commonly deployed — discovery is best-effort only
_COMMON_DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "k2",
    "selector1", "selector2",   # Microsoft 365
    "s1", "s2",
    "mandrill", "mailchimp", "sendgrid",
    "em",                        # SendGrid legacy
    "protonmail",
    "zoho",
    # Brevo / Sendinblue
    "brevo1", "brevo2", "brevo3", "brevo4",
    "sendinblue", "sendinblue1", "sendinblue2",
    # Mailjet
    "mailjet", "mailjet1", "mailjet2",
    # SMTP2Go
    "smtp2go", "smtp2go1", "smtp2go2",
    # Postmark
    "pm", "pm1", "pm2", "pm3",
    # SendGrid additional
    "s3", "s4", "k3", "k4", "k5",
    # Mailgun
    "mg", "mg1", "mg2", "mg3", "mailo",
    # SparkPost / Bird
    "scph0702", "scph1220", "scph0120",
    # Amazon SES
    "ses", "amazonses", "ses-dkim",
    # Elastic Email
    "elastic", "ee", "eedkim",
    # HubSpot
    "hs1", "hs2", "hubspot", "hubspot1",
    # Klaviyo
    "klaviyo", "kl", "kl1", "kl2",
    # Salesforce / ExactTarget
    "et1", "et2", "sfmc", "exacttarget",
    # Campaign Monitor
    "cm", "cm1", "cm2",
    # MailerLite
    "mailerlite", "ml1", "ml2",
    # ActiveCampaign
    "ac1", "ac2",
    # Constant Contact
    "cc1", "cc2",
    # Zoho
    "zoho", "zoho1",
    # Netcore / Pepipost
    "pepipost", "netcore",
    # Infomaniak
    "infomaniak",
    # Gandi
    "gandi1",
    # OVH
    "ovh1",
    # SendPulse
    "sendpulse",
    # Drip
    "drip",
    # GetResponse
    "gr1", "getresponse",
    # Generic common
    "info", "noreply", "newsletter", "marketing",
    "smtp", "relay", "outbound", "transactional",
    "dkim1", "dkim2", "sig1", "sig2",
]

# Weak key size thresholds (RSA bits)
_RSA_MINIMUM_BITS = 1024
_RSA_RECOMMENDED_BITS = 2048


def _make_resolver(timeout: float = 5.0, use_system: bool = False) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    if not use_system:
        r.nameservers = _PUBLIC_NS
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


async def _engine_resolver(timeout: float = 5.0):
    """
    Resolver used by DNSAuthEngine._run.

    Always built through the module-level ``_make_resolver`` factory (the
    injection point tests patch). _run used to call dns_utils.get_resolver()
    directly, bypassing that factory: the patched resolver was ignored, the
    engine hit real DNS/crt.sh and test_engine_completes_without_error timed
    out. The public-DNS reachability fallback of dns_utils is preserved for
    real resolvers only.
    """
    resolver = _make_resolver(timeout=timeout)
    if isinstance(resolver, dns.asyncresolver.Resolver):
        from app.engines import dns_utils
        if dns_utils._public_dns_ok is None:
            dns_utils._public_dns_ok = await dns_utils._probe_public()
        if not dns_utils._public_dns_ok:
            resolver = _make_resolver(timeout=timeout, use_system=True)
    return resolver


# RFC 2606 / RFC 6761 reserved names: never resolvable on the public
# Internet, so no external lookups (CT logs, policy fetch) are attempted.
_RESERVED_TLDS = (".invalid", ".test", ".example", ".localhost", ".local")


class _SkipLookup(Exception):
    """Internal: an optional external lookup is intentionally not performed."""


def _is_reserved_name(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d.endswith(t) or d == t.lstrip(".") for t in _RESERVED_TLDS)


async def _query_txt(resolver: dns.asyncresolver.Resolver, name: str) -> list[str]:
    """Return TXT record strings for name, or empty list on NXDOMAIN/NoAnswer."""
    try:
        answer = await resolver.resolve(name, "TXT")
        records = []
        for rdata in answer:
            txt = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            records.append(txt)
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        raise


async def _query_mx(
    resolver: dns.asyncresolver.Resolver, domain: str
) -> list[tuple[int, str]]:
    """Return [(priority, hostname)] sorted by priority."""
    try:
        answer = await resolver.resolve(domain, "MX")
        return sorted(
            [(int(rdata.preference), str(rdata.exchange).rstrip(".")) for rdata in answer],
            key=lambda x: x[0],
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        raise


# ── SPF Analyser ──────────────────────────────────────────────────────────────


@dataclass
class SPFResult:
    record: Optional[str] = None
    mechanisms: list[str] = field(default_factory=list)
    all_qualifier: Optional[str] = None  # "+", "-", "~", "?"
    lookup_count: int = 0
    exceeded_lookup_limit: bool = False
    has_permerror: bool = False
    has_temperror: bool = False
    includes: list[str] = field(default_factory=list)
    redirects: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None


class SPFAnalyser:
    name = "dns_auth"
    _DNS_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}
    _MAX_LOOKUPS = 10

    def __init__(self, resolver: dns.asyncresolver.Resolver) -> None:
        self._resolver = resolver
        self._lookup_count = 0
        self._visited_domains: set[str] = set()  # cycle detection

    async def analyse(self, domain: str) -> SPFResult:
        result = SPFResult()
        self._lookup_count = 0
        self._visited_domains = set()

        txts = await _query_txt(self._resolver, domain)
        spf_records = [t for t in txts if t.startswith("v=spf1")]

        if not spf_records:
            result.findings.append(Finding(
                engine=self.name,
                check_id="SPF-01",
                title="SPF record absent",
                description=(
                    f"No SPF record found for {domain}. Without SPF, anyone can send "
                    "email claiming to be from this domain and email providers have "
                    "no policy to validate the sender."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.ABSENCE,
                    observed_value=None,
                    expected_value="v=spf1 ... -all",
                    source=f"DNS TXT {domain}",
                )],
                remediation=(
                    "Publish an SPF record: v=spf1 include:<mailprovider> -all\n"
                    "Use '-all' to reject unauthorized senders."
                ),
                affected_asset=domain,
                business_impact="Enables email spoofing and phishing from your domain.",
                references=["https://datatracker.ietf.org/doc/html/rfc7208"],
            ))
            return result

        if len(spf_records) > 1:
            result.findings.append(Finding(
                engine=self.name,
                check_id="SPF-02",
                title="Multiple SPF records (permerror)",
                description=(
                    f"{domain} has {len(spf_records)} SPF TXT records. "
                    "RFC7208 §3.2 requires exactly one. Multiple records cause "
                    "a permanent SPF evaluation error (permerror)."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=1.0,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value="; ".join(spf_records),
                    expected_value="Exactly one SPF record",
                    source=f"DNS TXT {domain}",
                )],
                remediation="Merge all SPF mechanisms into a single TXT record.",
                affected_asset=domain,
                references=["https://datatracker.ietf.org/doc/html/rfc7208#section-3.2"],
            ))
            result.has_permerror = True

        spf = spf_records[0]
        result.record = spf

        await self._parse_record(domain, spf, result, depth=0)
        self._score_all_qualifier(domain, spf, result)
        self._check_lookup_limit(domain, result)

        return result

    async def _parse_record(
        self, domain: str, record: str, result: SPFResult, depth: int
    ) -> None:
        if depth > 10:
            result.has_permerror = True
            return

        # Cycle detection: if this domain was already visited, stop
        if domain in self._visited_domains:
            result.has_permerror = True
            return
        self._visited_domains.add(domain)

        parts = record.split()
        for part in parts[1:]:  # skip v=spf1
            lower = part.lower()
            qualifier = "+"
            mechanism = lower
            if lower and lower[0] in "+-~?":
                qualifier = lower[0]
                mechanism = lower[1:]

            mech_name = mechanism.split(":")[0].split("/")[0]

            result.mechanisms.append(part)

            if mech_name in self._DNS_LOOKUP_MECHANISMS:
                self._lookup_count += 1
                result.lookup_count = self._lookup_count

                if mech_name == "include":
                    target = part.split(":", 1)[1] if ":" in part else ""
                    if target:
                        result.includes.append(target)
                        try:
                            sub_txts = await _query_txt(self._resolver, target)
                            sub_spf = next((t for t in sub_txts if t.startswith("v=spf1")), None)
                            if sub_spf and self._lookup_count < self._MAX_LOOKUPS:
                                await self._parse_record(target, sub_spf, result, depth + 1)
                        except dns.exception.Timeout:
                            result.has_temperror = True

                elif mech_name == "redirect":
                    target = mechanism.split("=", 1)[1] if "=" in mechanism else ""
                    if target:
                        result.redirects.append(target)
                        try:
                            sub_txts = await _query_txt(self._resolver, target)
                            sub_spf = next((t for t in sub_txts if t.startswith("v=spf1")), None)
                            if sub_spf:
                                await self._parse_record(target, sub_spf, result, depth + 1)
                        except dns.exception.Timeout:
                            result.has_temperror = True

            if mech_name == "all":
                result.all_qualifier = qualifier

    def _score_all_qualifier(self, domain: str, record: str, result: SPFResult) -> None:
        q = result.all_qualifier

        if q == "+":
            result.findings.append(Finding(
                engine=self.name,
                check_id="SPF-03",
                title="SPF allows all senders (+all)",
                description=(
                    f"The SPF record for {domain} ends with '+all', which authorizes "
                    "any IP on the internet to send email as this domain. This renders "
                    "SPF completely ineffective."
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=1.0,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=record,
                    expected_value="Ends with -all or ~all",
                    source=f"DNS TXT {domain}",
                )],
                remediation=(
                    "Replace '+all' with '-all' to reject unauthorized senders. "
                    "If you are unsure of all sending sources, use '~all' temporarily "
                    "while auditing, then harden to '-all'."
                ),
                affected_asset=domain,
                business_impact="Anyone can send email claiming to be from this domain.",
                references=["https://datatracker.ietf.org/doc/html/rfc7208#section-5.1"],
            ))

        elif q == "~":
            result.findings.append(Finding(
                engine=self.name,
                check_id="SPF-04",
                title="SPF uses softfail (~all)",
                description=(
                    f"The SPF record for {domain} ends with '~all' (softfail). "
                    "Unauthorized senders are marked but not rejected. This reduces "
                    "phishing friction but does not prevent delivery."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=record,
                    expected_value="Ends with -all",
                    source=f"DNS TXT {domain}",
                )],
                remediation=(
                    "Consider hardening to '-all' once all legitimate sending sources "
                    "are enumerated. Monitor DMARC reports to identify missing sources."
                ),
                affected_asset=domain,
                references=["https://datatracker.ietf.org/doc/html/rfc7208#section-5.5"],
            ))

        elif q == "?":
            result.findings.append(Finding(
                engine=self.name,
                check_id="SPF-05b",
                title="SPF uses neutral all (?all) — no enforcement",
                description=(
                    f"The SPF record for {domain} ends with '?all' (neutral). "
                    "This provides no enforcement: unauthorized senders pass with a "
                    "'neutral' result, which most receivers treat the same as 'none'."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=record,
                    expected_value="Ends with -all",
                    source=f"DNS TXT {domain}",
                )],
                remediation="Replace '?all' with '-all' to enforce SPF rejection.",
                affected_asset=domain,
            ))

        elif q is None:
            result.findings.append(Finding(
                engine=self.name,
                check_id="SPF-05",
                title="SPF record has no 'all' mechanism",
                description=(
                    f"The SPF record for {domain} does not include an 'all' mechanism. "
                    "Without it, the default result is 'neutral', allowing all senders."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.85,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=record,
                    expected_value="Ends with -all or ~all",
                    source=f"DNS TXT {domain}",
                )],
                remediation="Add '-all' as the final mechanism in your SPF record.",
                affected_asset=domain,
            ))

    def _check_lookup_limit(self, domain: str, result: SPFResult) -> None:
        if result.lookup_count > self._MAX_LOOKUPS:
            result.exceeded_lookup_limit = True
            result.has_permerror = True
            result.findings.append(Finding(
                engine=self.name,
                check_id="SPF-06",
                title=f"SPF exceeds 10 DNS lookup limit (permerror)",
                description=(
                    f"SPF evaluation for {domain} requires {result.lookup_count} DNS lookups, "
                    "exceeding the RFC7208 limit of 10. Mail receivers that enforce this limit "
                    "will return a permanent error, potentially causing legitimate mail to fail."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.ANALYSIS,
                    observed_value=f"{result.lookup_count} lookups",
                    expected_value="≤ 10 lookups",
                    source=f"SPF evaluation tree for {domain}",
                    technical_details={"includes": result.includes, "redirects": result.redirects},
                )],
                remediation=(
                    "Flatten your SPF record by replacing nested includes with direct "
                    "ip4:/ip6: mechanisms. Consider using an SPF flattening service or "
                    "consolidating sending infrastructure."
                ),
                affected_asset=domain,
                references=["https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4"],
            ))

        if result.has_temperror:
            result.findings.append(Finding(
                engine=self.name,
                check_id="SPF-07",
                title="SPF evaluation encountered DNS timeout (temperror)",
                description=(
                    f"DNS lookups during SPF evaluation for {domain} timed out. "
                    "Mail receivers may return 'temperror', causing temporary delivery failures."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.7,
                evidence=[Evidence(
                    type=EvidenceType.TIMEOUT,
                    observed_value="DNS timeout during include resolution",
                    source=f"SPF evaluation for {domain}",
                )],
                remediation=(
                    "Verify that all domains referenced in SPF include: directives "
                    "have healthy DNS. Remove includes for defunct services."
                ),
                affected_asset=domain,
            ))


# ── DKIM Analyser ─────────────────────────────────────────────────────────────


@dataclass
class DKIMSelectorResult:
    selector: str
    found: bool = False
    record: Optional[str] = None
    key_type: Optional[str] = None
    key_bits: Optional[int] = None
    flags: Optional[str] = None
    error: Optional[str] = None


class DKIMAnalyser:
    name = "dns_auth"

    def __init__(
        self,
        resolver: dns.asyncresolver.Resolver,
        selectors: Optional[list[str]] = None,
    ) -> None:
        self._resolver = resolver
        self._selectors = selectors or _COMMON_DKIM_SELECTORS

    async def analyse(self, domain: str) -> tuple[list[DKIMSelectorResult], list[Finding]]:
        results = []
        findings: list[Finding] = []
        found_any = False

        # A wildcard *._domainkey record answers every selector with the same value;
        # reporting it once per probed selector would flood the results.
        wildcard_records = await self._wildcard_records(domain)

        for selector in self._selectors:
            name = f"{selector}._domainkey.{domain}"
            txts = []
            try:
                txts = await _query_txt(self._resolver, name)
            except dns.exception.Timeout:
                pass

            dkim_records = [t for t in txts if "v=DKIM1" in t or "k=" in t or "p=" in t]
            if wildcard_records:
                dkim_records = [t for t in dkim_records if t not in wildcard_records]

            if not dkim_records:
                results.append(DKIMSelectorResult(selector=selector, found=False))
                continue

            found_any = True
            for record in dkim_records:
                r = DKIMSelectorResult(selector=selector, found=True, record=record)
                self._parse_dkim_record(record, r)
                results.append(r)

                # Check for revoked key (p=)
                if self._is_revoked(record):
                    findings.append(Finding(
                        engine=self.name,
                        check_id="DKIM-02",
                        title=f"DKIM key revoked for selector '{selector}'",
                        description=(
                            f"Selector {selector}._domainkey.{domain} has an empty p= value, "
                            "meaning the DKIM key is explicitly revoked. Mail signed with "
                            "this selector will fail DKIM verification."
                        ),
                        risk_level=RiskLevel.MEDIUM,
                        confidence=1.0,
                        evidence=[Evidence(
                            type=EvidenceType.DNS_RECORD,
                            observed_value=record,
                            source=f"DNS TXT {name}",
                        )],
                        remediation=(
                            "Remove the revoked selector DNS record if no longer needed, "
                            "or publish a new valid DKIM key for this selector."
                        ),
                        affected_asset=name,
                    ))

                elif r.key_type == "rsa" and r.key_bits and r.key_bits < _RSA_MINIMUM_BITS:
                    findings.append(Finding(
                        engine=self.name,
                        check_id="DKIM-03",
                        title=f"DKIM RSA key too short ({r.key_bits} bits) for selector '{selector}'",
                        description=(
                            f"The DKIM key at {name} uses RSA-{r.key_bits}, below the "
                            f"minimum recommended {_RSA_RECOMMENDED_BITS} bits. "
                            "Short keys can be factored by well-resourced adversaries."
                        ),
                        risk_level=RiskLevel.HIGH,
                        confidence=0.95,
                        evidence=[Evidence(
                            type=EvidenceType.DNS_RECORD,
                            observed_value=f"RSA {r.key_bits} bits",
                            expected_value=f"RSA ≥ {_RSA_RECOMMENDED_BITS} bits",
                            source=f"DNS TXT {name}",
                        )],
                        remediation=f"Rotate the DKIM key to RSA-{_RSA_RECOMMENDED_BITS} or use Ed25519.",
                        affected_asset=name,
                    ))

                elif r.key_type == "rsa" and r.key_bits and r.key_bits < _RSA_RECOMMENDED_BITS:
                    findings.append(Finding(
                        engine=self.name,
                        check_id="DKIM-04",
                        title=f"DKIM RSA key below recommended size ({r.key_bits} bits)",
                        description=(
                            f"The DKIM key at {name} uses RSA-{r.key_bits}. "
                            f"The recommended minimum is {_RSA_RECOMMENDED_BITS} bits."
                        ),
                        risk_level=RiskLevel.LOW,
                        confidence=0.9,
                        evidence=[Evidence(
                            type=EvidenceType.DNS_RECORD,
                            observed_value=f"RSA {r.key_bits} bits",
                            expected_value=f"RSA ≥ {_RSA_RECOMMENDED_BITS} bits",
                            source=f"DNS TXT {name}",
                        )],
                        remediation=f"Consider rotating to RSA-{_RSA_RECOMMENDED_BITS} or Ed25519.",
                        affected_asset=name,
                    ))

        if wildcard_records:
            null_wildcard = all(self._is_revoked(t) for t in wildcard_records)
            findings.append(Finding(
                engine=self.name,
                check_id="DKIM-05",
                title=(
                    "Wildcard null DKIM record (domain declares it signs no mail)"
                    if null_wildcard else "Wildcard DKIM record published"
                ),
                description=(
                    f"*._domainkey.{domain} answers every selector with the same record. "
                    + (
                        "The key is empty (p=), which is the recommended way for a domain that "
                        "sends no mail to make any DKIM signature fail."
                        if null_wildcard else
                        "A single key for every selector prevents per-sender key rotation and "
                        "makes it impossible to tell which selectors are really in use."
                    )
                ),
                risk_level=RiskLevel.INFO if null_wildcard else RiskLevel.LOW,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=wildcard_records[0],
                    source=f"DNS TXT *._domainkey.{domain}",
                )],
                remediation=(
                    "No action needed if the domain sends no mail. Otherwise publish "
                    "per-selector keys and remove the wildcard."
                    if null_wildcard else
                    "Publish one key per selector and remove the wildcard record."
                ),
                affected_asset=f"*._domainkey.{domain}",
            ))

        if not found_any and not wildcard_records:
            # Note: absence ≠ no DKIM. The domain may use selectors not in our list.
            findings.append(Finding(
                engine=self.name,
                check_id="DKIM-01",
                title="No DKIM selectors discovered",
                description=(
                    f"None of the {len(self._selectors)} commonly used DKIM selectors "
                    f"were found for {domain}. This does NOT confirm DKIM is absent — "
                    "the domain may use selectors outside the discovery list."
                ),
                risk_level=RiskLevel.INFO,
                confidence=0.5,
                evidence=[Evidence(
                    type=EvidenceType.ABSENCE,
                    observed_value=f"Checked selectors: {', '.join(self._selectors[:8])}…",
                    expected_value="At least one valid DKIM selector",
                    source=f"DNS TXT *._domainkey.{domain}",
                )],
                remediation=(
                    "Verify DKIM is configured with your email provider. "
                    "If a custom selector is used, provide it for a targeted check."
                ),
                affected_asset=domain,
            ))

        return results, findings

    def _parse_dkim_record(self, record: str, result: DKIMSelectorResult) -> None:
        tags = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip().lower()] = v.strip()

        result.key_type = tags.get("k", "rsa").lower()
        result.flags = tags.get("t")
        p = tags.get("p", "")

        if result.key_type == "rsa" and p:
            try:
                import base64
                from cryptography.hazmat.primitives.serialization import load_der_public_key
                der = base64.b64decode(p + "==")
                key = load_der_public_key(der)
                result.key_bits = key.key_size
            except Exception:
                pass

    async def _wildcard_records(self, domain: str) -> list[str]:
        probe = f"mailox-wildcard-probe-9q7x._domainkey.{domain}"
        try:
            txts = await _query_txt(self._resolver, probe)
        except dns.exception.Timeout:
            return []
        return [t for t in txts if "v=DKIM1" in t or "k=" in t or "p=" in t]

    def _is_revoked(self, record: str) -> bool:
        for part in record.split(";"):
            part = part.strip()
            if part.lower().startswith("p=") and part[2:].strip() == "":
                return True
        return False


# ── DMARC Analyser ────────────────────────────────────────────────────────────


@dataclass
class DMARCResult:
    record: Optional[str] = None
    policy: Optional[str] = None      # none, quarantine, reject
    sp: Optional[str] = None          # subdomain policy
    pct: int = 100
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    adkim: str = "r"
    aspf: str = "r"
    fo: str = "0"
    ri: int = 86400
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None


class DMARCAnalyser:
    name = "dns_auth"

    def __init__(self, resolver: dns.asyncresolver.Resolver) -> None:
        self._resolver = resolver

    async def analyse(self, domain: str) -> DMARCResult:
        result = DMARCResult()
        dmarc_name = f"_dmarc.{domain}"

        txts = []
        try:
            txts = await _query_txt(self._resolver, dmarc_name)
        except dns.exception.Timeout:
            result.error = "DNS timeout querying DMARC record"
            return result

        dmarc_records = [t for t in txts if t.startswith("v=DMARC1")]

        if not dmarc_records:
            result.findings.append(Finding(
                engine=self.name,
                check_id="DMARC-01",
                title="DMARC record absent",
                description=(
                    f"No DMARC record found at {dmarc_name}. "
                    "Without DMARC, email receivers cannot determine how to handle "
                    "messages that fail SPF and DKIM checks, and no aggregate reporting "
                    "is configured to detect spoofing attempts."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.ABSENCE,
                    observed_value=None,
                    expected_value='v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com',
                    source=f"DNS TXT {dmarc_name}",
                )],
                remediation=(
                    "Publish a DMARC record starting with p=none to begin monitoring, "
                    "then graduate to p=quarantine and p=reject after reviewing reports."
                ),
                affected_asset=domain,
                business_impact=(
                    "Without DMARC, spoofed emails from your domain reach recipients "
                    "and you have no visibility into unauthorized sending."
                ),
                references=["https://datatracker.ietf.org/doc/html/rfc7489"],
            ))
            return result

        if len(dmarc_records) > 1:
            result.findings.append(Finding(
                engine=self.name,
                check_id="DMARC-02",
                title="Multiple DMARC records found",
                description=(
                    f"{dmarc_name} has {len(dmarc_records)} DMARC TXT records. "
                    "RFC7489 requires exactly one. This results in undefined behavior."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=1.0,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value="; ".join(dmarc_records),
                    expected_value="Exactly one DMARC record",
                    source=f"DNS TXT {dmarc_name}",
                )],
                remediation="Remove duplicate DMARC records, keeping only one.",
                affected_asset=domain,
            ))

        record = dmarc_records[0]
        result.record = record
        self._parse_record(record, result)
        self._score_policy(domain, record, result)
        self._check_reporting(domain, record, result)
        self._check_pct(domain, record, result)

        return result

    def _parse_record(self, record: str, result: DMARCResult) -> None:
        tags: dict[str, str] = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip().lower()] = v.strip()

        result.policy = tags.get("p")
        result.sp = tags.get("sp")
        result.adkim = tags.get("adkim", "r")
        result.aspf = tags.get("aspf", "r")
        result.fo = tags.get("fo", "0")

        try:
            result.pct = int(tags.get("pct", "100"))
        except ValueError:
            result.pct = 100

        try:
            result.ri = int(tags.get("ri", "86400"))
        except ValueError:
            result.ri = 86400

        rua = tags.get("rua", "")
        if rua:
            result.rua = [u.strip() for u in rua.split(",")]

        ruf = tags.get("ruf", "")
        if ruf:
            result.ruf = [u.strip() for u in ruf.split(",")]

    def _score_policy(self, domain: str, record: str, result: DMARCResult) -> None:
        p = result.policy

        if p is None:
            result.findings.append(Finding(
                engine=self.name,
                check_id="DMARC-03",
                title="DMARC record missing policy tag (p=)",
                description=(
                    f"The DMARC record for {domain} does not contain a valid p= tag. "
                    "This is a syntax error — receivers treat it as invalid."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=record,
                    expected_value="Contains p=none, p=quarantine, or p=reject",
                    source=f"DNS TXT _dmarc.{domain}",
                )],
                remediation="Add a valid p= tag to your DMARC record.",
                affected_asset=domain,
            ))
        elif p == "none":
            result.findings.append(Finding(
                engine=self.name,
                check_id="DMARC-04",
                title="DMARC policy is 'none' (monitoring only)",
                description=(
                    f"The DMARC policy for {domain} is p=none. This means receivers "
                    "take no action on failing messages — it is a monitoring-only posture. "
                    "Spoofed emails are delivered normally."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=record,
                    expected_value="p=quarantine or p=reject",
                    source=f"DNS TXT _dmarc.{domain}",
                )],
                remediation=(
                    "Review DMARC aggregate reports (rua=) to identify all legitimate "
                    "sending sources, then graduate to p=quarantine, then p=reject."
                ),
                affected_asset=domain,
                business_impact=(
                    "Spoofed emails from this domain are delivered to recipients. "
                    "p=none is appropriate only during initial deployment."
                ),
            ))
        elif p == "quarantine":
            result.findings.append(Finding(
                engine=self.name,
                check_id="DMARC-05",
                title="DMARC policy is 'quarantine' (partial enforcement)",
                description=(
                    f"The DMARC policy for {domain} is p=quarantine. "
                    "Failing messages are sent to spam/junk but not rejected outright."
                ),
                risk_level=RiskLevel.LOW,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=record,
                    expected_value="p=reject",
                    source=f"DNS TXT _dmarc.{domain}",
                )],
                remediation=(
                    "Consider graduating to p=reject once you are confident all "
                    "legitimate sending is covered by SPF and DKIM."
                ),
                affected_asset=domain,
            ))
        # p=reject — no finding (this is the desired state)

    def _check_reporting(self, domain: str, record: str, result: DMARCResult) -> None:
        if not result.rua:
            result.findings.append(Finding(
                engine=self.name,
                check_id="DMARC-06",
                title="DMARC aggregate reporting (rua=) not configured",
                description=(
                    f"The DMARC record for {domain} has no rua= tag. "
                    "Without aggregate reporting, you have no visibility into "
                    "emails that fail DMARC checks or unauthorized sending activity."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=record,
                    expected_value="Contains rua=mailto:...",
                    source=f"DNS TXT _dmarc.{domain}",
                )],
                remediation=(
                    "Add rua=mailto:dmarc-reports@yourdomain.com to receive "
                    "aggregate XML reports from mail receivers."
                ),
                affected_asset=domain,
            ))

    def _check_pct(self, domain: str, record: str, result: DMARCResult) -> None:
        if result.pct < 100 and result.policy in ("quarantine", "reject"):
            result.findings.append(Finding(
                engine=self.name,
                check_id="DMARC-07",
                title=f"DMARC policy applied to only {result.pct}% of messages",
                description=(
                    f"The DMARC record for {domain} specifies pct={result.pct}, "
                    f"meaning the {result.policy} policy applies to only {result.pct}% "
                    "of failing messages. The remaining messages are treated as p=none."
                ),
                risk_level=RiskLevel.LOW,
                confidence=0.9,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value=f"pct={result.pct}",
                    expected_value="pct=100",
                    source=f"DNS TXT _dmarc.{domain}",
                )],
                remediation="Increase pct= to 100 when confident all legitimate email passes DMARC.",
                affected_asset=domain,
            ))


# ── MTA-STS + TLS-RPT checks ─────────────────────────────────────────────────

def _mta_sts_transport():
    """HTTPS transport for the MTA-STS policy fetch: SSRF-guarded, DNS-pinned, verify=True."""
    from app.engines.ssrf_guard import SSRFGuard
    from app.engines.webmail_transport import PinnedDNSTransport
    return PinnedDNSTransport(ssrf_guard=SSRFGuard(), verify=True)


def _iter_exc_chain(exc: BaseException):
    seen: set[int] = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        yield cur
        cur = cur.__cause__ or cur.__context__


def _exc_chain_has(exc: BaseException, exc_type: type) -> bool:
    return any(isinstance(e, exc_type) for e in _iter_exc_chain(exc))


def _tls_cert_error(exc: BaseException) -> Optional[str]:
    """Return a description if exc (or its cause chain) is a certificate validation failure."""
    import ssl
    for e in _iter_exc_chain(exc):
        if isinstance(e, ssl.SSLCertVerificationError):
            return getattr(e, "verify_message", None) or str(e)
        msg = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in msg or "certificate verify failed" in msg.lower():
            return msg
    return None


async def _check_mta_sts(
    resolver: dns.asyncresolver.Resolver,
    domain: str,
) -> tuple[list, dict]:
    """Check MTA-STS DNS record and policy file."""
    findings = []
    meta: dict[str, Any] = {"record": None, "mode": None, "policy_reachable": None}

    # 1. DNS TXT record at _mta-sts.domain
    mta_sts_name = f"_mta-sts.{domain}"
    try:
        txts = await _query_txt(resolver, mta_sts_name)
        sts_records = [t for t in txts if t.startswith("v=STSv1")]
        if not sts_records:
            findings.append(Finding(
                engine="dns_auth",
                check_id="MTAS-01",
                title="MTA-STS not configured",
                description=(
                    f"No MTA-STS TXT record found at {mta_sts_name}. "
                    "MTA-STS (RFC 8461) lets receiving domains mandate TLS for inbound mail, "
                    "preventing STARTTLS downgrade attacks and certificate stripping."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value="NXDOMAIN or no v=STSv1 record",
                    expected_value=f"TXT {mta_sts_name} v=STSv1; id=...",
                    source=f"DNS TXT {mta_sts_name}",
                )],
                remediation=(
                    "1. Create HTTPS endpoint: https://mta-sts.{domain}/.well-known/mta-sts.txt\n"
                    "2. Publish policy file with: version: STSv1, mode: enforce, mx: ..., max_age: 86400\n"
                    "3. Add DNS TXT: _mta-sts.{domain} → v=STSv1; id=<timestamp>"
                ),
                affected_asset=domain,
                business_impact=(
                    "Attackers can intercept email in transit via STARTTLS downgrade. "
                    "Without MTA-STS, TLS is opportunistic and unverified."
                ),
            ))
            return findings, meta

        record = sts_records[0]
        meta["record"] = record

        # 2. Check policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt
        import httpx
        from app.engines.ssrf_guard import SSRFGuardError
        policy_host = f"mta-sts.{domain}"
        policy_url = f"https://{policy_host}/.well-known/mta-sts.txt"
        try:
            # RFC 8461 §3.3: the policy MUST be fetched over HTTPS with a valid
            # certificate for mta-sts.<domain>, and redirects MUST NOT be
            # followed. The pinned transport also applies the SSRF guard
            # (no private/metadata IPs, no DNS-rebinding between check and use).
            async with httpx.AsyncClient(
                transport=_mta_sts_transport(),
                timeout=8.0,
                follow_redirects=False,
                headers={"User-Agent": SCANNER_USER_AGENT},
            ) as client:
                resp = await client.get(policy_url)
            if resp.status_code == 200:
                meta["policy_reachable"] = True
                body = resp.text
                mode_match = re.search(r"mode:\s*(\w+)", body)
                mode = mode_match.group(1).lower() if mode_match else None
                meta["mode"] = mode
                if mode == "testing":
                    findings.append(Finding(
                        engine="dns_auth",
                        check_id="MTAS-02",
                        title="MTA-STS policy in 'testing' mode (not enforced)",
                        description=(
                            f"MTA-STS policy at {policy_url} has mode: testing. "
                            "Receiving MTAs will report violations but not enforce TLS. "
                            "STARTTLS downgrade attacks are still possible."
                        ),
                        risk_level=RiskLevel.LOW,
                        confidence=0.95,
                        evidence=[Evidence(
                            type=EvidenceType.HTTP_RESPONSE,
                            observed_value="mode: testing",
                            expected_value="mode: enforce",
                            source=policy_url,
                        )],
                        remediation=(
                            "Change policy file to: mode: enforce\n"
                            "Monitor TLS-RPT reports for failures before switching."
                        ),
                        affected_asset=domain,
                    ))
                elif mode == "none":
                    findings.append(Finding(
                        engine="dns_auth",
                        check_id="MTAS-03",
                        title="MTA-STS policy is 'none' (explicitly disabled)",
                        description=(
                            f"MTA-STS policy at {policy_url} has mode: none. "
                            "This is equivalent to having no MTA-STS policy at all."
                        ),
                        risk_level=RiskLevel.MEDIUM,
                        confidence=0.95,
                        evidence=[Evidence(
                            type=EvidenceType.HTTP_RESPONSE,
                            observed_value="mode: none",
                            expected_value="mode: enforce",
                            source=policy_url,
                        )],
                        remediation="Set mode: enforce in the MTA-STS policy file.",
                        affected_asset=domain,
                    ))
                # mode: enforce → no finding (desired state)
            else:
                meta["policy_reachable"] = False
                findings.append(Finding(
                    engine="dns_auth",
                    check_id="MTAS-04",
                    title="MTA-STS DNS record exists but policy file unreachable",
                    description=(
                        f"DNS TXT record {mta_sts_name} exists (v=STSv1) but the policy file "
                        f"at {policy_url} returned HTTP {resp.status_code}. "
                        "MTAs will treat this as a broken MTA-STS deployment and fall back to opportunistic TLS."
                    ),
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.9,
                    evidence=[Evidence(
                        type=EvidenceType.HTTP_RESPONSE,
                        observed_value=f"HTTP {resp.status_code}",
                        expected_value="HTTP 200 with policy body",
                        source=policy_url,
                    )],
                    remediation=(
                        f"Ensure {policy_url} is reachable over HTTPS with a valid certificate "
                        "and returns a properly formatted MTA-STS policy."
                    ),
                    affected_asset=domain,
                ))
        except Exception as exc:
            meta["policy_reachable"] = False
            cert_error = _tls_cert_error(exc)
            if _exc_chain_has(exc, SSRFGuardError):
                # Policy host resolves to a non-public address: not fetched.
                meta["policy_error"] = "ssrf_blocked"
            elif cert_error:
                meta["policy_error"] = "invalid_certificate"
                findings.append(Finding(
                    engine="dns_auth",
                    check_id="MTAS-05",
                    title="MTA-STS policy host presents an invalid TLS certificate",
                    description=(
                        f"DNS TXT record {mta_sts_name} exists (v=STSv1) but the HTTPS "
                        f"certificate of {policy_host} failed validation ({cert_error}). "
                        "RFC 8461 §3.3 requires a valid certificate for the policy host: "
                        "sending MTAs will not load this policy, so MTA-STS is not applied "
                        "and TLS for inbound mail stays opportunistic."
                    ),
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.9,
                    evidence=[Evidence(
                        type=EvidenceType.TLS_CERTIFICATE,
                        observed_value=cert_error[:300],
                        expected_value=f"Certificate valid for {policy_host}, chaining to a public root",
                        source=policy_url,
                        technical_details={"policy_host": policy_host, "tls_error": cert_error[:500]},
                    )],
                    remediation=(
                        f"Serve {policy_url} with a certificate that is valid for {policy_host} "
                        "(correct SAN, unexpired, publicly trusted chain), e.g. via Let's Encrypt."
                    ),
                    affected_asset=policy_host,
                    business_impact=(
                        "A broken MTA-STS policy endpoint silently disables MTA-STS: "
                        "STARTTLS downgrade and MX spoofing remain possible."
                    ),
                    references=["https://www.rfc-editor.org/rfc/rfc8461#section-3.3"],
                ))
            else:
                meta["policy_error"] = type(exc).__name__

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        findings.append(Finding(
            engine="dns_auth",
            check_id="MTAS-01",
            title="MTA-STS not configured",
            description=(
                f"No MTA-STS TXT record found at {mta_sts_name}. "
                "MTA-STS (RFC 8461) lets receiving domains mandate TLS for inbound mail, "
                "preventing STARTTLS downgrade attacks and certificate stripping."
            ),
            risk_level=RiskLevel.MEDIUM,
            confidence=0.95,
            evidence=[Evidence(
                type=EvidenceType.DNS_RECORD,
                observed_value="NXDOMAIN",
                expected_value=f"TXT {mta_sts_name} v=STSv1; id=...",
                source=f"DNS TXT {mta_sts_name}",
            )],
            remediation=(
                "1. Host policy at https://mta-sts.{domain}/.well-known/mta-sts.txt\n"
                "2. Add DNS TXT: _mta-sts.{domain} → v=STSv1; id=<timestamp>"
            ),
            affected_asset=domain,
            business_impact=(
                "Without MTA-STS, STARTTLS is opportunistic and unverified — "
                "downgrade to cleartext is trivially possible."
            ),
        ))
    except Exception:
        pass

    return findings, meta


async def _check_tls_rpt(
    resolver: dns.asyncresolver.Resolver,
    domain: str,
) -> list:
    """Check TLS-RPT (RFC 8460) reporting record."""
    findings = []
    tlsrpt_name = f"_smtp._tls.{domain}"
    try:
        txts = await _query_txt(resolver, tlsrpt_name)
        rpt_records = [t for t in txts if t.startswith("v=TLSRPTv1")]
        if not rpt_records:
            findings.append(Finding(
                engine="dns_auth",
                check_id="TLSRPT-01",
                title="TLS-RPT not configured",
                description=(
                    f"No TLS-RPT record at {tlsrpt_name}. "
                    "TLS-RPT (RFC 8460) enables MTAs to report TLS negotiation failures, "
                    "MTA-STS policy violations, and DANE errors to the domain owner. "
                    "Without it, email channel failures are invisible."
                ),
                risk_level=RiskLevel.LOW,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.DNS_RECORD,
                    observed_value="NXDOMAIN or no v=TLSRPTv1 record",
                    expected_value=f"TXT {tlsrpt_name} v=TLSRPTv1; rua=mailto:...",
                    source=f"DNS TXT {tlsrpt_name}",
                )],
                remediation=(
                    f"Add DNS TXT: {tlsrpt_name} → v=TLSRPTv1; rua=mailto:tls-rpt@{domain}\n"
                    "Reports are JSON (RFC 8460 Appendix A) sent daily by MTAs."
                ),
                affected_asset=domain,
            ))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        findings.append(Finding(
            engine="dns_auth",
            check_id="TLSRPT-01",
            title="TLS-RPT not configured",
            description=(
                f"No TLS-RPT record at {tlsrpt_name}. "
                "Without TLS-RPT, delivery failures due to TLS negotiation errors "
                "or MTA-STS policy violations are invisible to the domain owner."
            ),
            risk_level=RiskLevel.LOW,
            confidence=0.95,
            evidence=[Evidence(
                type=EvidenceType.DNS_RECORD,
                observed_value="NXDOMAIN",
                expected_value=f"TXT {tlsrpt_name} v=TLSRPTv1; rua=mailto:...",
                source=f"DNS TXT {tlsrpt_name}",
            )],
            remediation=f"Add: {tlsrpt_name} → v=TLSRPTv1; rua=mailto:tls-rpt@{domain}",
            affected_asset=domain,
        ))
    except Exception:
        pass
    return findings


# ── DNS Auth Engine ───────────────────────────────────────────────────────────


class DNSAuthEngine(BaseEngine):
    name = "dns_auth"
    default_timeout = 45.0

    def __init__(
        self,
        timeout: Optional[float] = None,
        dkim_selectors: Optional[list[str]] = None,
    ) -> None:
        super().__init__(timeout)
        self._dkim_selectors = dkim_selectors

    async def _run(self, domain: str) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)
        resolver = await _engine_resolver(timeout=5.0)

        # SPF
        try:
            spf_analyser = SPFAnalyser(resolver)
            spf_result = await spf_analyser.analyse(domain)
            result.findings.extend(spf_result.findings)
            result.metadata["spf"] = {
                "record": spf_result.record,
                "all_qualifier": spf_result.all_qualifier,
                "lookup_count": spf_result.lookup_count,
                "includes": spf_result.includes,
            }
        except Exception as e:
            self.logger.error("spf_analysis_failed", domain=domain, error=type(e).__name__)
            result.metadata["spf_error"] = type(e).__name__

        # DKIM
        try:
            dkim_analyser = DKIMAnalyser(resolver, selectors=self._dkim_selectors)
            dkim_selectors_found, dkim_findings = await dkim_analyser.analyse(domain)
            result.findings.extend(dkim_findings)
            result.metadata["dkim"] = {
                "selectors_checked": len(dkim_analyser._selectors),
                "selectors_found": [
                    {"selector": r.selector, "key_type": r.key_type, "key_bits": r.key_bits}
                    for r in dkim_selectors_found
                    if r.found
                ],
            }
        except Exception as e:
            self.logger.error("dkim_analysis_failed", domain=domain, error=type(e).__name__)
            result.metadata["dkim_error"] = type(e).__name__

        # DMARC
        try:
            dmarc_analyser = DMARCAnalyser(resolver)
            dmarc_result = await dmarc_analyser.analyse(domain)
            result.findings.extend(dmarc_result.findings)
            result.metadata["dmarc"] = {
                "record": dmarc_result.record,
                "policy": dmarc_result.policy,
                "pct": dmarc_result.pct,
                "rua": dmarc_result.rua,
                "ruf": dmarc_result.ruf,
            }
        except Exception as e:
            self.logger.error("dmarc_analysis_failed", domain=domain, error=type(e).__name__)
            result.metadata["dmarc_error"] = type(e).__name__

        # MTA-STS + TLS-RPT
        try:
            mta_findings, mta_meta = await _check_mta_sts(resolver, domain)
            result.findings.extend(mta_findings)
            result.metadata["mta_sts"] = mta_meta
        except Exception as e:
            self.logger.error("mta_sts_check_failed", domain=domain, error=type(e).__name__)

        try:
            tlsrpt_findings = await _check_tls_rpt(resolver, domain)
            result.findings.extend(tlsrpt_findings)
        except Exception as e:
            self.logger.error("tls_rpt_check_failed", domain=domain, error=type(e).__name__)

        # Provider fingerprinting — identify ESP/gateway from MX, SPF, DKIM signals
        try:
            from app.engines.provider_fingerprint import (
                fingerprint_from_mx, fingerprint_from_spf,
                fingerprint_from_dkim_selectors, fingerprint_from_txt_records,
                fingerprint_hosting_from_ptr, fingerprint_hosting_from_rdap,
                fingerprint_selfhosted_from_mx, merge_provider_matches,
            )
            _fp_matches = []

            # From MX hostnames
            _mx_raw = await _query_mx(resolver, domain)
            _mx_hosts = [host.rstrip(".") for _, host in _mx_raw]
            _fp_matches.extend(fingerprint_from_mx(_mx_hosts))
            _fp_matches.extend(fingerprint_selfhosted_from_mx(_mx_hosts, domain))
            result.metadata["mx_hosts"] = _mx_hosts

            # From SPF record
            _spf_record: str = result.metadata.get("spf", {}).get("record") or ""
            if _spf_record:
                _fp_matches.extend(fingerprint_from_spf(_spf_record))

            # From DKIM selectors found
            _dkim_selectors_found = [
                s["selector"]
                for s in result.metadata.get("dkim", {}).get("selectors_found", [])
            ]
            if _dkim_selectors_found:
                _fp_matches.extend(fingerprint_from_dkim_selectors(_dkim_selectors_found))

            # From TXT records (brevo-code:, sendgrid-verification:, etc.)
            _all_txts = await _query_txt(resolver, domain)
            _fp_matches.extend(fingerprint_from_txt_records(_all_txts))

            # From PTR + RDAP on resolved MX IPs
            _resolved_ips: list[str] = []
            for _mx_host in _mx_hosts[:3]:
                try:
                    _a_ans = await resolver.resolve(_mx_host, "A")
                    for _rdata in list(_a_ans)[:2]:
                        _ip = str(_rdata)
                        _resolved_ips.append(_ip)
                        try:
                            import ipaddress as _ipmod
                            _rev = _ipmod.ip_address(_ip).reverse_pointer
                            _ptr_ans = await resolver.resolve(_rev + ".", "PTR")
                            for _ptr_rdata in list(_ptr_ans)[:1]:
                                _ptr = str(_ptr_rdata).rstrip(".")
                                _hosting = fingerprint_hosting_from_ptr(_ptr)
                                if _hosting:
                                    _fp_matches.append(_hosting)
                                result.metadata.setdefault("ptr_records", {})[_ip] = _ptr
                        except Exception:
                            pass
                except Exception:
                    pass

            # RDAP lookup for first MX IP (more reliable than PTR for hosting ID)
            if _resolved_ips:
                try:
                    _rdap_match = await fingerprint_hosting_from_rdap(_resolved_ips[0])
                    if _rdap_match:
                        _fp_matches.append(_rdap_match)
                        result.metadata.setdefault("rdap", {})["org"] = _rdap_match.signals[0] if _rdap_match.signals else ""
                except Exception:
                    pass

            _providers = merge_provider_matches(_fp_matches)
            result.metadata["providers"] = [
                {
                    "name": p.name,
                    "confidence": round(p.confidence, 2),
                    "type": p.provider_type,
                    "signals": p.signals,
                }
                for p in _providers
            ]

            # INFO findings — ESP + hosting identified separately
            if _providers:
                from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel
                _esps = [p for p in _providers if p.provider_type in ("esp", "gateway", "selfhosted")]
                _hosters = [p for p in _providers if p.provider_type == "hosting"]

                if _esps:
                    _esp_names = ", ".join(p.name for p in _esps)
                    _all_signals = [s for p in _esps for s in p.signals]
                    result.findings.append(Finding(
                        engine="dns_auth",
                        check_id="DNS-PROVIDER-01",
                        # Full list goes in the description/evidence: a long list
                        # (10+ ESPs) overflowed the 255-char title column.
                        title=_summary_title("Mail provider identified", [p.name for p in _esps]),
                        description=(
                            f"Mail infrastructure for {domain} uses: {_esp_names}. "
                            + (f"Signals: {'; '.join(_all_signals[:5])}." if _all_signals else "")
                        ),
                        risk_level=RiskLevel.INFO,
                        confidence=_esps[0].confidence,
                        evidence=[Evidence(
                            type=EvidenceType.DNS_RECORD,
                            observed_value=", ".join(_all_signals[:8]),
                            source=f"DNS MX+SPF+DKIM+TXT {domain}",
                            technical_details={"providers": [
                                {"name": p.name, "type": p.provider_type, "signals": p.signals}
                                for p in _providers
                            ]},
                        )],
                        remediation="",
                        affected_asset=domain,
                    ))

                if _hosters:
                    _host_names = ", ".join(p.name for p in _hosters)
                    _host_signals = [s for p in _hosters for s in p.signals]
                    result.findings.append(Finding(
                        engine="dns_auth",
                        check_id="DNS-HOSTING-01",
                        title=_summary_title("Mail server hosted on", [p.name for p in _hosters]),
                        description=(
                            f"The MX server for {domain} is hosted on {_host_names}. "
                            + (f"Identified from: {'; '.join(_host_signals[:3])}." if _host_signals else "")
                        ),
                        risk_level=RiskLevel.INFO,
                        confidence=_hosters[0].confidence,
                        evidence=[Evidence(
                            type=EvidenceType.DNS_RECORD,
                            observed_value=", ".join(_host_signals[:5]),
                            source=f"PTR {domain}",
                            technical_details={"hosting": [
                                {"name": p.name, "signals": p.signals} for p in _hosters
                            ]},
                        )],
                        remediation="",
                        affected_asset=domain,
                    ))
        except Exception as e:
            self.logger.warning("provider_fingerprint_failed", domain=domain, error=str(e))

        # MX subdomain checks — run full dns_auth on each MX host that is a subdomain of target
        # e.g. scanning elmatgar.com discovers mail.elmatgar.com and checks it too
        try:
            mx_records = await _query_mx(resolver, domain)
            seen_mx_hosts: set[str] = set()
            for _prio, mx_host in mx_records:
                mx_host = mx_host.lower().rstrip(".")
                if mx_host in seen_mx_hosts or mx_host == domain:
                    continue
                # Only check subdomains of the target — skip 3rd party MTAs (gmail, etc.)
                if not mx_host.endswith(f".{domain}"):
                    continue
                seen_mx_hosts.add(mx_host)
                self.logger.info("dns_auth_mx_subdomain", domain=domain, mx_host=mx_host)
                try:
                    spf_a = SPFAnalyser(resolver)
                    spf_r = await spf_a.analyse(mx_host)
                    result.findings.extend(spf_r.findings)
                except Exception:
                    pass
                try:
                    dkim_a = DKIMAnalyser(resolver, selectors=self._dkim_selectors)
                    _, dkim_f = await dkim_a.analyse(mx_host)
                    result.findings.extend(dkim_f)
                except Exception:
                    pass
                try:
                    dmarc_a = DMARCAnalyser(resolver)
                    dmarc_r = await dmarc_a.analyse(mx_host)
                    result.findings.extend(dmarc_r.findings)
                except Exception:
                    pass
                try:
                    mta_f, _ = await _check_mta_sts(resolver, mx_host)
                    result.findings.extend(mta_f)
                except Exception:
                    pass
                try:
                    tlsrpt_f = await _check_tls_rpt(resolver, mx_host)
                    result.findings.extend(tlsrpt_f)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error("mx_subdomain_checks_failed", domain=domain, error=type(e).__name__)

        # IP Reputation / RBL check for MX server IPs
        try:
            _RBL_ZONES = [
                ("zen.spamhaus.org",       "Spamhaus ZEN"),
                ("b.barracudacentral.org", "Barracuda"),
                ("bl.spamcop.net",         "SpamCop"),
                ("dnsbl.sorbs.net",        "SORBS"),
            ]
            _rbl_hits: list[tuple[str, str, str]] = []
            _rbl_checked_ips: list[str] = list(result.metadata.get("ptr_records", {}).keys())
            if not _rbl_checked_ips:
                _mx_raw2 = await _query_mx(resolver, domain)
                for _, _mxh in _mx_raw2[:2]:
                    try:
                        _a2 = await resolver.resolve(_mxh.rstrip("."), "A")
                        for _r2 in list(_a2)[:1]:
                            _rbl_checked_ips.append(str(_r2))
                    except Exception:
                        pass

            for _ip in _rbl_checked_ips[:2]:
                try:
                    _rev_ip = ".".join(reversed(_ip.split(".")))
                    for _zone, _zone_name in _RBL_ZONES:
                        try:
                            _rbl_ans = await resolver.resolve(f"{_rev_ip}.{_zone}", "A")
                            _code = str(list(_rbl_ans)[0]) if _rbl_ans else "listed"
                            _rbl_hits.append((_ip, _zone_name, _code))
                        except Exception:
                            pass  # NXDOMAIN = clean
                except Exception:
                    pass

            result.metadata["rbl_hits"] = [
                {"ip": ip, "list": z, "code": c} for ip, z, c in _rbl_hits
            ]
            result.metadata["rbl_checked_ips"] = _rbl_checked_ips

            if _rbl_hits:
                from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel
                for _rbl_ip, _rbl_zone, _rbl_code in _rbl_hits:
                    result.findings.append(Finding(
                        engine="dns_auth",
                        check_id=f"DNS-RBL-{_rbl_zone.upper().replace(' ', '-').replace('.', '')}",
                        title=f"MX server IP {_rbl_ip} listed on {_rbl_zone}",
                        description=(
                            f"The IP address {_rbl_ip} serving mail for {domain} is listed "
                            f"on the {_rbl_zone} DNS blacklist (return code: {_rbl_code}). "
                            "Receiving mail servers may reject or junk email from this IP."
                        ),
                        risk_level=RiskLevel.HIGH,
                        confidence=0.95,
                        evidence=[Evidence(
                            type=EvidenceType.DNS_RECORD,
                            observed_value=f"{_rbl_ip} → {_rbl_zone} ({_rbl_code})",
                            expected_value="NXDOMAIN (not listed)",
                            source=f"RBL lookup: {_rbl_ip}",
                        )],
                        remediation=(
                            f"Request delisting from {_rbl_zone}. "
                            "Identify and fix the spam/abuse issue causing the listing. "
                            "Consider dedicated IPs via your ESP if on shared hosting."
                        ),
                        affected_asset=_rbl_ip,
                        business_impact=(
                            "Blacklisted IPs cause email to be rejected or junked by major "
                            "providers (Gmail, Outlook, Yahoo). Critical deliverability issue."
                        ),
                    ))
        except Exception as _rbl_err:
            self.logger.debug("rbl_check_failed", domain=domain, error=str(_rbl_err))

        # Certificate Transparency — discover mail-related subdomains via crt.sh
        try:
            if _is_reserved_name(domain):
                raise _SkipLookup("reserved name")
            import httpx as _httpx
            # `async with` so the connection pool is closed (the bare
            # AsyncClient(...).get() leaked one client per scan).
            async with _httpx.AsyncClient(timeout=8.0, follow_redirects=True) as _ct_client:
                _ct_resp = await _ct_client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"Accept": "application/json"},
                )
            if _ct_resp.status_code == 200:
                _ct_entries: list[dict] = _ct_resp.json()
                _mail_subs: set[str] = set()
                _mail_prefixes = ("mail.", "smtp.", "mta.", "mx.", "mx1.", "mx2.", "webmail.",
                                  "owa.", "imap.", "pop.", "relay.", "outbound.", "send.")
                for _entry in _ct_entries:
                    _name = (_entry.get("name_value") or "").lower().strip()
                    for _sub in _name.split("\n"):
                        _sub = _sub.strip().lstrip("*.")
                        if _sub.endswith(f".{domain}") or _sub == domain:
                            for _prefix in _mail_prefixes:
                                if _sub.startswith(_prefix):
                                    _mail_subs.add(_sub)
                                    break
                result.metadata["ct_mail_subdomains"] = sorted(_mail_subs)
                if _mail_subs:
                    from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel
                    result.findings.append(Finding(
                        engine="dns_auth",
                        check_id="DNS-CT-01",
                        title=f"Mail-related subdomains found in CT logs: {', '.join(sorted(_mail_subs)[:5])}",
                        description=(
                            f"Certificate Transparency logs reveal {len(_mail_subs)} mail-related "
                            f"subdomain(s) for {domain}: {', '.join(sorted(_mail_subs))}. "
                            "Each may expose SMTP, IMAP, or webmail services worth scanning."
                        ),
                        risk_level=RiskLevel.INFO,
                        confidence=0.95,
                        evidence=[Evidence(
                            type=EvidenceType.DNS_RECORD,
                            observed_value=", ".join(sorted(_mail_subs)),
                            source="crt.sh Certificate Transparency",
                        )],
                        remediation="",
                        affected_asset=domain,
                    ))
        except Exception as _ct_err:
            self.logger.debug("ct_lookup_failed", domain=domain, error=str(_ct_err))

        return result
