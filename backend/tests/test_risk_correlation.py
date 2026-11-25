"""
RiskCorrelationEngine tests.
"""
import pytest

from app.engines.risk_correlation import RiskCorrelationEngine
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel


def _finding(check_id: str, risk: RiskLevel, confidence: float = 0.9) -> Finding:
    return Finding(
        engine="test",
        check_id=check_id,
        title=f"Test: {check_id}",
        description="test finding",
        risk_level=risk,
        confidence=confidence,
        evidence=[Evidence(
            type=EvidenceType.ANALYSIS,
            observed_value="test",
            source="https://example.com/",
        )],
        remediation="fix it",
        affected_asset="example.com",
    )


class TestBaseScore:
    def test_empty_findings_returns_zero(self):
        engine = RiskCorrelationEngine()
        result = engine.run("example.com", [])
        assert result.risk_score == 0.0
        assert result.findings == []
        assert result.chains == []

    def test_single_critical_contributes(self):
        engine = RiskCorrelationEngine()
        result = engine.run("example.com", [_finding("SOME-CHECK", RiskLevel.CRITICAL)])
        # 25.0 * 0.9 = 22.5
        assert result.risk_score > 0.0

    def test_info_findings_do_not_contribute_to_base(self):
        engine = RiskCorrelationEngine()
        infos = [_finding(f"DA-INFO-{i}", RiskLevel.INFO) for i in range(10)]
        result = engine.run("example.com", infos)
        # Info weight = 0, no chains triggered → score = 0
        assert result.risk_score == 0.0

    def test_score_capped_at_100(self):
        engine = RiskCorrelationEngine()
        # Many criticals + all chains triggered → must not exceed 100
        findings = [_finding(f"SMTP-OPEN-RELAY-{i}", RiskLevel.CRITICAL) for i in range(10)]
        findings += [_finding("SPF-01", RiskLevel.HIGH)]
        findings += [_finding("DMARC-01", RiskLevel.HIGH)]
        findings += [_finding("DKIM-01", RiskLevel.HIGH)]
        findings += [_finding("SE-SMTP-CRED", RiskLevel.CRITICAL)]
        result = engine.run("example.com", findings)
        assert result.risk_score <= 100.0

    def test_severity_ordering(self):
        engine = RiskCorrelationEngine()
        r_crit = engine.run("example.com", [_finding("X", RiskLevel.CRITICAL)])
        r_high = engine.run("example.com", [_finding("X", RiskLevel.HIGH)])
        r_med = engine.run("example.com", [_finding("X", RiskLevel.MEDIUM)])
        r_low = engine.run("example.com", [_finding("X", RiskLevel.LOW)])
        assert r_crit.risk_score > r_high.risk_score > r_med.risk_score > r_low.risk_score

    def test_confidence_scales_score(self):
        engine = RiskCorrelationEngine()
        r_high_conf = engine.run("example.com", [_finding("X", RiskLevel.HIGH, confidence=1.0)])
        r_low_conf = engine.run("example.com", [_finding("X", RiskLevel.HIGH, confidence=0.1)])
        assert r_high_conf.risk_score > r_low_conf.risk_score


class TestFindingCounts:
    def test_counts_by_level_populated(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("A", RiskLevel.CRITICAL),
            _finding("B", RiskLevel.HIGH),
            _finding("C", RiskLevel.HIGH),
            _finding("D", RiskLevel.MEDIUM),
        ]
        result = engine.run("example.com", findings)
        assert result.finding_count_by_level["critical"] == 1
        assert result.finding_count_by_level["high"] == 2
        assert result.finding_count_by_level["medium"] == 1
        assert result.finding_count_by_level["low"] == 0
        assert result.finding_count_by_level["info"] == 0


class TestPhishingChainRule:
    def test_relay_plus_spf_triggers_chain(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SMTP-OPEN-RELAY", RiskLevel.HIGH),
            _finding("SPF-01", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-PHISHING-CHAIN" in chain_ids

    def test_relay_plus_dmarc_triggers_chain(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SMTP-RELAY-OPEN", RiskLevel.HIGH),
            _finding("DMARC-NONE-POLICY", RiskLevel.MEDIUM),
        ]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-PHISHING-CHAIN" in chain_ids

    def test_relay_alone_no_phishing_chain(self):
        engine = RiskCorrelationEngine()
        findings = [_finding("SMTP-OPEN-RELAY", RiskLevel.HIGH)]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-PHISHING-CHAIN" not in chain_ids

    def test_phishing_chain_produces_synthetic_finding(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SMTP-OPEN-RELAY", RiskLevel.HIGH),
            _finding("SPF-01", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        chain_checks = [f.check_id for f in result.findings]
        assert "RC-PHISHING-CHAIN" in chain_checks

    def test_phishing_chain_finding_is_critical(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SMTP-OPEN-RELAY", RiskLevel.MEDIUM),
            _finding("SPF-PERMISSIVE", RiskLevel.LOW),
        ]
        result = engine.run("example.com", findings)
        for f in result.findings:
            if f.check_id == "RC-PHISHING-CHAIN":
                assert f.risk_level == RiskLevel.CRITICAL


class TestWebmailCVEStackRule:
    def test_cve_plus_tls_triggers_chain(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("VI-CVE-2024-37383", RiskLevel.HIGH),
            _finding("WM-TLS-EXPIRED", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-WEBMAIL-CVE-STACK" in chain_ids

    def test_cve_critical_plus_tls_triggers_chain(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("VI-CVE-2024-45519", RiskLevel.CRITICAL),
            _finding("WM-TLS-SELF-SIGNED", RiskLevel.MEDIUM),
        ]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-WEBMAIL-CVE-STACK" in chain_ids

    def test_low_cve_plus_tls_no_chain(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("VI-CVE-2024-99999", RiskLevel.LOW),  # LOW CVE
            _finding("WM-TLS-EXPIRED", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-WEBMAIL-CVE-STACK" not in chain_ids

    def test_cve_alone_no_chain(self):
        engine = RiskCorrelationEngine()
        findings = [_finding("VI-CVE-2024-37383", RiskLevel.HIGH)]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-WEBMAIL-CVE-STACK" not in chain_ids


class TestCredOpenRelayRule:
    def test_secret_plus_relay_triggers_chain(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SE-SMTP-PASSWORD", RiskLevel.CRITICAL),
            _finding("SMTP-OPEN-RELAY", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-CRED-OPEN-RELAY" in chain_ids

    def test_secret_alone_no_cred_relay_chain(self):
        engine = RiskCorrelationEngine()
        findings = [_finding("SE-SMTP-PASSWORD", RiskLevel.CRITICAL)]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-CRED-OPEN-RELAY" not in chain_ids

    def test_cred_relay_chain_is_critical(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SE-SMTP-PASSWORD", RiskLevel.CRITICAL),
            _finding("SMTP-RELAY-OPEN", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        for c in result.chains:
            if c.rule_id == "RC-CRED-OPEN-RELAY":
                from app.schemas.findings import RiskLevel as RL
                assert c.severity == RL.CRITICAL


class TestAuthFailureClusterRule:
    def test_all_three_missing_triggers_cluster(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SPF-01", RiskLevel.HIGH),
            _finding("DKIM-01", RiskLevel.HIGH),
            _finding("DMARC-01", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-AUTH-FAILURE-CLUSTER" in chain_ids

    def test_two_missing_triggers_cluster(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SPF-01", RiskLevel.HIGH),
            _finding("DMARC-01", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-AUTH-FAILURE-CLUSTER" in chain_ids

    def test_one_missing_no_cluster(self):
        engine = RiskCorrelationEngine()
        findings = [_finding("SPF-01", RiskLevel.HIGH)]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-AUTH-FAILURE-CLUSTER" not in chain_ids


class TestStackedCriticalsRule:
    def test_three_criticals_triggers_rule(self):
        engine = RiskCorrelationEngine()
        findings = [_finding(f"CRIT-{i}", RiskLevel.CRITICAL) for i in range(3)]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-STACKED-CRITICALS" in chain_ids

    def test_three_criticals_enforces_score_floor(self):
        engine = RiskCorrelationEngine()
        # 3 small criticals (low confidence) → base score might be low
        findings = [_finding(f"CRIT-{i}", RiskLevel.CRITICAL, confidence=0.1) for i in range(3)]
        result = engine.run("example.com", findings)
        assert result.risk_score >= 85.0

    def test_two_criticals_no_stacked_rule(self):
        engine = RiskCorrelationEngine()
        findings = [_finding(f"CRIT-{i}", RiskLevel.CRITICAL) for i in range(2)]
        result = engine.run("example.com", findings)
        chain_ids = [c.rule_id for c in result.chains]
        assert "RC-STACKED-CRITICALS" not in chain_ids

    def test_stacked_criticals_does_not_produce_synthetic_finding(self):
        engine = RiskCorrelationEngine()
        findings = [_finding(f"CRIT-{i}", RiskLevel.CRITICAL) for i in range(3)]
        result = engine.run("example.com", findings)
        # RC-STACKED-CRITICALS has no synthetic finding (only floor enforcement)
        chain_checks = [f.check_id for f in result.findings]
        assert "RC-STACKED-CRITICALS" not in chain_checks


class TestSyntheticFindingStructure:
    def test_synthetic_finding_has_risk_correlation_engine(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SMTP-OPEN-RELAY", RiskLevel.HIGH),
            _finding("SPF-01", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        for f in result.findings:
            assert f.engine == "risk_correlation"

    def test_synthetic_finding_evidence_has_rule_id(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SMTP-OPEN-RELAY", RiskLevel.HIGH),
            _finding("SPF-01", RiskLevel.HIGH),
        ]
        result = engine.run("example.com", findings)
        for f in result.findings:
            assert len(f.evidence) > 0
            td = f.evidence[0].technical_details
            assert td is not None
            assert "rule_id" in td

    def test_domain_in_affected_asset(self):
        engine = RiskCorrelationEngine()
        findings = [
            _finding("SMTP-OPEN-RELAY", RiskLevel.HIGH),
            _finding("SPF-01", RiskLevel.HIGH),
        ]
        result = engine.run("mail.example.com", findings)
        for f in result.findings:
            assert f.affected_asset == "mail.example.com"
