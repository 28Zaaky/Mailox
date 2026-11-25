"""
Module 08 — Security Correlation & Risk Engine.

Consumes all findings from a completed scan, identifies cross-finding
relationships, and produces an aggregate risk score (0-100) plus
synthetic correlation findings (check_id prefix RC-).

Risk score formula:
  base = sum(weight[risk_level] * confidence for each finding)
  amplification rules can push the score higher
  final = min(100, base + amplifications)

Correlation rules (5):
  RC-PHISHING-CHAIN          weak SPF/DMARC + open relay → CRITICAL cluster
  RC-WEBMAIL-CVE-STACK       CVE HIGH/CRIT + TLS issue on same asset → amplify
  RC-CRED-OPEN-RELAY         SMTP credential exposed + open relay → CRITICAL
  RC-AUTH-FAILURE-CLUSTER    SPF+DKIM+DMARC all absent/weak → HIGH cluster
  RC-STACKED-CRITICALS       ≥3 CRITICAL findings → score floor 85
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel

# Weight per severity level (contribution to base score per finding)
_WEIGHTS: dict[RiskLevel, float] = {
    RiskLevel.CRITICAL: 25.0,
    RiskLevel.HIGH: 10.0,
    RiskLevel.MEDIUM: 4.0,
    RiskLevel.LOW: 1.0,
    RiskLevel.INFO: 0.0,
}

# check_id patterns per condition. Matching is exact or prefix (see
# _matches_any) — never substring: "tls-" used to match
# "AP-STARTTLS-NOTENFORCE-CLEAN" and "secret" any id containing that word.
# Real ids: dns_auth (SPF-/DKIM-/DMARC-nn), smtp_security (SMTPS-nn),
# webmail TLS (WM-TLS*), secrets (SE-*), vuln_intel (VI-CVE-*), active_probes (AP-*).
# Legacy/alias ids are kept so stored findings from older engines still count.
_OPEN_RELAY_IDS = {"SMTPS-04", "SMTP-08", "SMTP-RELAY", "SMTP-OPEN-RELAY", "OPEN-RELAY"}
_WEAK_SPF_IDS = {"SPF-01", "SPF-02", "SPF-03", "SPF-04", "SPF-05", "SPF-05b",
                 "SPF-PERMISSIVE", "SPF-ABSENT"}
_WEAK_DMARC_IDS = {"DMARC-01", "DMARC-02", "DMARC-03", "DMARC-04", "DMARC-05",
                   "DMARC-NONE", "DMARC-ABSENT"}
_WEAK_DKIM_IDS = {"DKIM-01", "DKIM-02", "DKIM-03", "DKIM-04", "DKIM-ABSENT"}
_AUTH_CLUSTER_MIN_CONFIDENCE = 0.7
_TLS_ISSUE_IDS = {"SMTPS-01", "SMTPS-02", "SMTPS-05", "SMTPS-06", "SMTPS-07", "SMTPS-09",
                  "SMTPS-10", "SMTPS-11", "SMTP-05", "SMTP-06", "SMTP-07", "SMTP-09",
                  "SMTP-10", "WM-TLS", "TLS-", "AP-STARTTLS-NOTENFORCE"}
_CVE_IDS = {"VI-CVE-"}
_SECRET_IDS = {"SE-"}


def _matches_any(check_id: str, patterns: set[str]) -> bool:
    """
    Exact or prefix match, case-insensitive.
    - pattern ending with "-" is a pure prefix ("VI-CVE-" -> "VI-CVE-2024-1")
    - otherwise: equal, or followed by "-"/"_" ("WM-TLS" -> "WM-TLS-EXPIRED",
      but "SPF-0" never matches "SPF-05" and "SMTPS-01" never "SMTPS-010")
    """
    cid = check_id.upper()
    for p in patterns:
        pu = p.upper()
        if pu.endswith("-"):
            if cid.startswith(pu):
                return True
        elif cid == pu or cid.startswith(pu + "-") or cid.startswith(pu + "_"):
            return True
    return False


def _is_problem(f: Finding) -> bool:
    """INFO findings and '*-CLEAN' results are observations, not weaknesses."""
    if f.risk_level == RiskLevel.INFO:
        return False
    cid = f.check_id.upper()
    return not (cid.endswith("-CLEAN") or cid.startswith("VI-CLEAN-"))


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (check_id, affected_asset); keep the most severe/confident."""
    order = {RiskLevel.CRITICAL: 4, RiskLevel.HIGH: 3, RiskLevel.MEDIUM: 2,
             RiskLevel.LOW: 1, RiskLevel.INFO: 0}
    best: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.check_id.upper(), (f.affected_asset or "").lower())
        cur = best.get(key)
        if cur is None or (order.get(f.risk_level, 0), f.confidence) > (order.get(cur.risk_level, 0), cur.confidence):
            best[key] = f
    return list(best.values())


@dataclass
class RiskChain:
    rule_id: str
    title: str
    description: str
    severity: RiskLevel
    contributing_check_ids: list[str] = field(default_factory=list)
    amplification: float = 0.0


@dataclass
class RiskCorrelationResult:
    risk_score: float
    findings: list[Finding]
    chains: list[RiskChain]
    finding_count_by_level: dict[str, int]


class RiskCorrelationEngine:

    def run(self, domain: str, findings: list[Finding]) -> RiskCorrelationResult:
        if not findings:
            return RiskCorrelationResult(
                risk_score=0.0,
                findings=[],
                chains=[],
                finding_count_by_level={lvl.value: 0 for lvl in RiskLevel},
            )

        all_findings = findings
        # Scoring and chain building only see real problems, once each.
        findings = _dedupe([f for f in all_findings if _is_problem(f)])

        base_score = self._base_score(findings)
        chains: list[RiskChain] = []
        synthetic: list[Finding] = []

        # Rule 1 — phishing chain
        chain1 = self._rule_phishing_chain(findings)
        if chain1:
            chains.append(chain1)
            synthetic.append(self._chain_to_finding(domain, chain1))

        # Rule 2 — webmail CVE stack
        chain2 = self._rule_webmail_cve_stack(findings)
        if chain2:
            chains.append(chain2)
            synthetic.append(self._chain_to_finding(domain, chain2))

        # Rule 3 — credential + open relay
        chain3 = self._rule_cred_open_relay(findings)
        if chain3:
            chains.append(chain3)
            synthetic.append(self._chain_to_finding(domain, chain3))

        # Rule 4 — auth failure cluster
        chain4 = self._rule_auth_failure_cluster(findings)
        if chain4:
            chains.append(chain4)
            synthetic.append(self._chain_to_finding(domain, chain4))

        # Rule 5 — stacked criticals
        chain5 = self._rule_stacked_criticals(findings)
        if chain5:
            chains.append(chain5)

        total_amp = sum(c.amplification for c in chains)
        raw_score = base_score + total_amp

        # Rule 5 enforces a floor
        if chain5:
            raw_score = max(raw_score, 85.0)

        final_score = min(100.0, raw_score)

        # Counts describe what the scan reported (all levels, as stored).
        counts = {lvl.value: 0 for lvl in RiskLevel}
        for f in all_findings:
            counts[f.risk_level.value] = counts.get(f.risk_level.value, 0) + 1

        return RiskCorrelationResult(
            risk_score=round(final_score, 1),
            findings=synthetic,
            chains=chains,
            finding_count_by_level=counts,
        )

    # ── Base score ────────────────────────────────────────────────────────────

    def _base_score(self, findings: list[Finding]) -> float:
        total = 0.0
        for f in _dedupe(findings):
            total += _WEIGHTS.get(f.risk_level, 0.0) * f.confidence
        return total

    # ── Correlation rules ─────────────────────────────────────────────────────

    def _rule_phishing_chain(self, findings: list[Finding]) -> Optional[RiskChain]:
        relay = [f for f in findings if _matches_any(f.check_id, _OPEN_RELAY_IDS)]
        spf = [f for f in findings if _matches_any(f.check_id, _WEAK_SPF_IDS)]
        dmarc = [f for f in findings if _matches_any(f.check_id, _WEAK_DMARC_IDS)]

        if not (relay and (spf or dmarc)):
            return None

        contributors = [f.check_id for f in relay + spf + dmarc]
        return RiskChain(
            rule_id="RC-PHISHING-CHAIN",
            title="Phishing Infrastructure Chain: Open Relay + Weak Email Authentication",
            description=(
                "An open SMTP relay combined with absent or permissive SPF/DMARC allows "
                "an attacker to send spoofed email from this domain with no filtering barrier. "
                "This chain enables high-confidence phishing campaigns targeting employees, "
                "customers, or partners."
            ),
            severity=RiskLevel.CRITICAL,
            contributing_check_ids=contributors,
            amplification=20.0,
        )

    def _rule_webmail_cve_stack(self, findings: list[Finding]) -> Optional[RiskChain]:
        cves = [f for f in findings if _matches_any(f.check_id, _CVE_IDS)
                and f.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
        tls_issues = [f for f in findings if _matches_any(f.check_id, _TLS_ISSUE_IDS)]

        if not (cves and tls_issues):
            return None

        contributors = [f.check_id for f in cves[:3] + tls_issues[:3]]
        return RiskChain(
            rule_id="RC-WEBMAIL-CVE-STACK",
            title="Webmail CVE + TLS Weakness Stack",
            description=(
                "A known high/critical CVE on the webmail interface is compounded by a TLS "
                "weakness. The TLS issue may expose session tokens or authentication credentials "
                "in transit, lowering the barrier for CVE exploitation."
            ),
            severity=RiskLevel.HIGH,
            contributing_check_ids=contributors,
            amplification=15.0,
        )

    def _rule_cred_open_relay(self, findings: list[Finding]) -> Optional[RiskChain]:
        secrets = [f for f in findings if _matches_any(f.check_id, _SECRET_IDS)]
        relay = [f for f in findings if _matches_any(f.check_id, _OPEN_RELAY_IDS)]

        if not (secrets and relay):
            return None

        contributors = [f.check_id for f in secrets[:3] + relay]
        return RiskChain(
            rule_id="RC-CRED-OPEN-RELAY",
            title="Credential Exposure + Open SMTP Relay",
            description=(
                "SMTP credentials exposed in source assets combined with an open relay "
                "gives an attacker both authentication material and an unrestricted sending "
                "path. Direct account takeover and mass spam/phishing are immediately achievable."
            ),
            severity=RiskLevel.CRITICAL,
            contributing_check_ids=contributors,
            amplification=25.0,
        )

    def _rule_auth_failure_cluster(self, findings: list[Finding]) -> Optional[RiskChain]:
        # Only established weaknesses count. "No DKIM selector discovered" (confidence 0.5)
        # means the selector list missed it, not that DKIM is absent.
        confirmed = [f for f in findings if f.confidence >= _AUTH_CLUSTER_MIN_CONFIDENCE]
        spf = [f for f in confirmed if _matches_any(f.check_id, _WEAK_SPF_IDS)]
        dkim = [f for f in confirmed if _matches_any(f.check_id, _WEAK_DKIM_IDS)]
        dmarc = [f for f in confirmed if _matches_any(f.check_id, _WEAK_DMARC_IDS)]

        weak = [name for name, hits in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)) if hits]
        if len(weak) < 2:
            return None

        contributors = [f.check_id for f in spf + dkim + dmarc]
        complete = len(weak) == 3
        return RiskChain(
            rule_id="RC-AUTH-FAILURE-CLUSTER",
            title="Complete Email Authentication Failure" if complete else "Weak Email Authentication",
            description=(
                f"{len(weak)}/3 email authentication mechanisms ({', '.join(weak)}) are absent "
                "or misconfigured. Together they leave the domain open to spoofing in phishing "
                "attacks" + (" with no technical barrier." if complete else ".")
            ),
            severity=RiskLevel.HIGH,
            contributing_check_ids=contributors,
            amplification=10.0,
        )

    def _rule_stacked_criticals(self, findings: list[Finding]) -> Optional[RiskChain]:
        criticals = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
        if len(criticals) < 3:
            return None

        return RiskChain(
            rule_id="RC-STACKED-CRITICALS",
            title=f"Multiple Critical Vulnerabilities ({len(criticals)} findings)",
            description=(
                f"{len(criticals)} independent critical findings detected. Each finding "
                "alone represents significant risk; the combination indicates a severely "
                "compromised security posture requiring immediate remediation."
            ),
            severity=RiskLevel.CRITICAL,
            contributing_check_ids=[f.check_id for f in criticals],
            amplification=0.0,  # floor enforced in caller, not via amplification
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _chain_to_finding(self, domain: str, chain: RiskChain) -> Finding:
        evidence_detail: dict[str, Any] = {
            "rule_id": chain.rule_id,
            "contributing_check_ids": chain.contributing_check_ids,
            "amplification": chain.amplification,
        }
        return Finding(
            id=uuid.uuid4(),
            engine="risk_correlation",
            check_id=chain.rule_id,
            title=chain.title,
            description=chain.description,
            risk_level=chain.severity,
            confidence=0.9,
            evidence=[
                Evidence(
                    type=EvidenceType.ANALYSIS,
                    observed_value=f"{len(chain.contributing_check_ids)} contributing findings",
                    source=f"https://{domain}/",
                    technical_details=evidence_detail,
                )
            ],
            remediation=(
                "Address each contributing finding. Risk chain dissolves when constituent "
                "vulnerabilities are remediated."
            ),
            affected_asset=domain,
            references=[],
        )
