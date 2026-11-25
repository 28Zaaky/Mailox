"""
ReportingEngine tests.
"""
import csv
import io
import json
from datetime import datetime, timezone

import pytest

from app.engines.reporting import ReportFinding, ReportScan, ReportingEngine


def _make_scan(**kwargs) -> ReportScan:
    defaults = dict(
        id="scan-id-123",
        org_id="org-id-456",
        target_domain="mail.example.com",
        status="completed",
        created_at=datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc),
        started_at=datetime(2026, 11, 16, 12, 0, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 11, 16, 12, 1, 0, tzinfo=timezone.utc),
        risk_score=42.5,
        finding_count=3,
        engine_runs=[],
    )
    defaults.update(kwargs)
    return ReportScan(**defaults)


def _make_finding(
    idx: int = 0,
    risk_level: str = "high",
    status: str = "open",
    engine: str = "dns_auth",
) -> ReportFinding:
    return ReportFinding(
        id=f"finding-{idx}",
        engine=engine,
        check_id=f"CHECK-{idx}",
        title=f"Test Finding {idx}",
        description=f"Description {idx}",
        risk_level=risk_level,
        confidence=0.9,
        affected_asset="mail.example.com",
        remediation="Fix it",
        evidence=[],
        references=[f"https://cve.example.com/{idx}"],
        status=status,
        cvss_score=7.5 if risk_level == "high" else None,
        created_at=datetime(2026, 11, 16, 12, 0, 30, tzinfo=timezone.utc),
        last_seen_at=None,
    )


class TestJSONFormat:
    def test_json_is_valid(self):
        engine = ReportingEngine()
        scan = _make_scan()
        findings = [_make_finding(i) for i in range(3)]
        content, ct = engine.generate(scan, findings, [], report_type="full", fmt="json")
        assert ct == "application/json"
        data = json.loads(content)
        assert isinstance(data, dict)

    def test_json_top_level_keys(self):
        engine = ReportingEngine()
        scan = _make_scan()
        content, _ = engine.generate(scan, [_make_finding()], [], report_type="full", fmt="json")
        data = json.loads(content)
        for key in ("report_type", "generated_at", "scan", "risk_summary", "chains", "findings"):
            assert key in data, f"Missing key: {key}"

    def test_json_scan_fields(self):
        engine = ReportingEngine()
        scan = _make_scan()
        content, _ = engine.generate(scan, [], [], fmt="json")
        data = json.loads(content)
        assert data["scan"]["target_domain"] == "mail.example.com"
        assert data["scan"]["risk_score"] == 42.5
        assert data["scan"]["status"] == "completed"

    def test_json_risk_summary_counts(self):
        engine = ReportingEngine()
        findings = [
            _make_finding(0, "critical"),
            _make_finding(1, "high"),
            _make_finding(2, "high"),
            _make_finding(3, "medium"),
        ]
        content, _ = engine.generate(_make_scan(), findings, [], fmt="json")
        data = json.loads(content)
        bysev = data["risk_summary"]["by_severity"]
        assert bysev["critical"] == 1
        assert bysev["high"] == 2
        assert bysev["medium"] == 1

    def test_json_full_has_description_and_evidence(self):
        engine = ReportingEngine()
        content, _ = engine.generate(_make_scan(), [_make_finding()], [], report_type="full", fmt="json")
        data = json.loads(content)
        f = data["findings"][0]
        assert "description" in f
        assert "remediation" in f

    def test_json_executive_omits_description(self):
        engine = ReportingEngine()
        # Executive only shows CRITICAL/HIGH, up to 20
        findings = [_make_finding(0, "critical")]
        content, _ = engine.generate(_make_scan(), findings, [], report_type="executive", fmt="json")
        data = json.loads(content)
        # description omitted in executive serialization
        f = data["findings"][0]
        assert "description" not in f

    def test_json_executive_filters_low_severity(self):
        engine = ReportingEngine()
        findings = [
            _make_finding(0, "critical"),
            _make_finding(1, "low"),
            _make_finding(2, "info"),
        ]
        content, _ = engine.generate(_make_scan(), findings, [], report_type="executive", fmt="json")
        data = json.loads(content)
        returned_risk_levels = {f["risk_level"] for f in data["findings"]}
        assert "low" not in returned_risk_levels
        assert "info" not in returned_risk_levels

    def test_json_zero_findings_valid(self):
        engine = ReportingEngine()
        content, _ = engine.generate(_make_scan(finding_count=0), [], [], fmt="json")
        data = json.loads(content)
        assert data["findings"] == []
        assert data["risk_summary"]["total_findings"] == 0

    def test_json_chains_included(self):
        engine = ReportingEngine()
        chains = [{"rule_id": "RC-PHISHING-CHAIN", "title": "Phishing", "description": "...", "severity": "critical"}]
        content, _ = engine.generate(_make_scan(), [_make_finding()], chains, fmt="json")
        data = json.loads(content)
        assert len(data["chains"]) == 1
        assert data["chains"][0]["rule_id"] == "RC-PHISHING-CHAIN"

    def test_json_posture_label(self):
        engine = ReportingEngine()
        content_crit, _ = engine.generate(_make_scan(risk_score=80.0), [], [], fmt="json")
        content_low, _ = engine.generate(_make_scan(risk_score=10.0), [], [], fmt="json")
        assert json.loads(content_crit)["risk_summary"]["posture"] == "critical"
        assert json.loads(content_low)["risk_summary"]["posture"] == "low"


class TestHTMLFormat:
    def test_html_content_type(self):
        engine = ReportingEngine()
        _, ct = engine.generate(_make_scan(), [_make_finding()], [], fmt="html")
        assert "text/html" in ct

    def test_html_contains_domain(self):
        engine = ReportingEngine()
        content, _ = engine.generate(_make_scan(), [_make_finding()], [], fmt="html")
        assert "mail.example.com" in content

    def test_html_contains_finding_title(self):
        engine = ReportingEngine()
        content, _ = engine.generate(_make_scan(), [_make_finding(0)], [], fmt="html")
        assert "Test Finding 0" in content

    def test_html_non_empty(self):
        engine = ReportingEngine()
        content, _ = engine.generate(_make_scan(), [], [], fmt="html")
        assert len(content) > 500

    def test_html_xss_escaping(self):
        engine = ReportingEngine()
        malicious_finding = _make_finding()
        malicious_finding.title = "<script>alert(1)</script>"
        content, _ = engine.generate(_make_scan(), [malicious_finding], [], fmt="html")
        # The template ships exactly one static inline <script> (print helper);
        # the injected one must not add a second, and must appear escaped.
        assert "<script>alert(1)</script>" not in content
        assert content.count("<script") == 1
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content

    def test_html_reference_js_scheme_not_linked(self):
        engine = ReportingEngine()
        f = _make_finding()
        f.references = ["javascript:alert(1)", "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"]
        content, _ = engine.generate(_make_scan(), [f], [], fmt="html", report_type="full")
        assert "href='javascript:" not in content
        assert "href='https://nvd.nist.gov/vuln/detail/CVE-2024-0001'" in content

    def test_html_zero_findings_graceful(self):
        engine = ReportingEngine()
        content, _ = engine.generate(_make_scan(finding_count=0), [], [], fmt="html")
        assert "0" in content  # finding count shown


class TestCSVFormat:
    def test_csv_content_type(self):
        engine = ReportingEngine()
        _, ct = engine.generate(_make_scan(), [_make_finding()], [], fmt="csv")
        assert "text/csv" in ct

    def test_csv_has_header(self):
        engine = ReportingEngine()
        content, _ = engine.generate(_make_scan(), [_make_finding()], [], fmt="csv")
        reader = csv.reader(io.StringIO(content))
        header = next(reader)
        assert "id" in header
        assert "risk_level" in header
        assert "affected_asset" in header
        assert "status" in header

    def test_csv_one_row_per_finding(self):
        engine = ReportingEngine()
        findings = [_make_finding(i) for i in range(5)]
        content, _ = engine.generate(_make_scan(), findings, [], fmt="csv")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        assert len(rows) == 6  # 1 header + 5 findings

    def test_csv_zero_findings(self):
        engine = ReportingEngine()
        content, _ = engine.generate(_make_scan(), [], [], fmt="csv")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        assert len(rows) == 1  # header only

    def test_csv_risk_level_in_rows(self):
        engine = ReportingEngine()
        findings = [_make_finding(0, "critical"), _make_finding(1, "low")]
        content, _ = engine.generate(_make_scan(), findings, [], fmt="csv")
        assert "critical" in content
        assert "low" in content


class TestReportTypeFiltering:
    def test_executive_max_20_findings(self):
        engine = ReportingEngine()
        findings = [_make_finding(i, "critical") for i in range(30)]
        content, _ = engine.generate(_make_scan(), findings, [], report_type="executive", fmt="json")
        data = json.loads(content)
        assert len(data["findings"]) <= 20

    def test_technical_includes_all_findings(self):
        engine = ReportingEngine()
        findings = [_make_finding(i, "low") for i in range(10)]
        content, _ = engine.generate(_make_scan(), findings, [], report_type="technical", fmt="json")
        data = json.loads(content)
        # technical includes LOW
        assert len(data["findings"]) == 10

    def test_full_includes_all_findings(self):
        engine = ReportingEngine()
        findings = [_make_finding(i, ["critical", "high", "medium", "low", "info"][i % 5]) for i in range(10)]
        content, _ = engine.generate(_make_scan(), findings, [], report_type="full", fmt="json")
        data = json.loads(content)
        assert len(data["findings"]) == 10

    def test_invalid_format_raises(self):
        engine = ReportingEngine()
        with pytest.raises(ValueError, match="Unsupported format"):
            engine.generate(_make_scan(), [], [], fmt="pdf")
