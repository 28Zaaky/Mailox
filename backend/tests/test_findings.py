"""
Findings management + Reports API tests.
"""
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.db.models.scan import FindingStatus, RiskLevel
from app.engines.reporting import ReportFinding, ReportScan, ReportingEngine
from app.schemas.phase5 import FindingResponse, FindingStatusUpdate


# ── FindingStatus enum ────────────────────────────────────────────────────────

class TestFindingStatusEnum:
    def test_all_lifecycle_states_present(self):
        values = {s.value for s in FindingStatus}
        expected = {"open", "confirmed", "accepted_risk", "in_remediation", "resolved", "false_positive"}
        assert values == expected

    def test_default_state_is_open(self):
        assert FindingStatus.OPEN.value == "open"

    def test_terminal_states_exist(self):
        assert FindingStatus.RESOLVED in FindingStatus
        assert FindingStatus.FALSE_POSITIVE in FindingStatus


# ── FindingStatusUpdate schema ────────────────────────────────────────────────

class TestFindingStatusUpdateSchema:
    def test_valid_status_accepted(self):
        for status in FindingStatus:
            obj = FindingStatusUpdate(status=status)
            assert obj.status == status

    def test_invalid_status_rejected(self):
        with pytest.raises(Exception):
            FindingStatusUpdate(status="nonexistent_status")


# ── FindingResponse schema ────────────────────────────────────────────────────

class TestFindingResponseSchema:
    def _make_db_obj(self, **overrides):
        obj = MagicMock()
        obj.id = uuid.uuid4()
        obj.scan_id = uuid.uuid4()
        obj.engine = "dns_auth"
        obj.check_id = "DA-SPF-ABSENT"
        obj.title = "SPF Record Absent"
        obj.description = "No SPF record."
        obj.risk_level = RiskLevel.HIGH
        obj.confidence = 0.9
        obj.affected_asset = "mail.example.com"
        obj.status = FindingStatus.OPEN
        obj.cvss_score = None
        obj.evidence = []
        obj.remediation = "Add SPF record."
        obj.references = []
        obj.created_at = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
        obj.last_seen_at = None
        # Dedup / state-workflow columns added to ScanFinding after this test was
        # written; a bare MagicMock would hand Pydantic mock objects for them.
        obj.fingerprint = None
        obj.status_changed_at = None
        obj.status_changed_by = None
        obj.state = "open"
        obj.state_note = None
        obj.state_updated_at = None
        for k, v in overrides.items():
            setattr(obj, k, v)
        return obj

    def test_serializes_uuid_as_string(self):
        obj = self._make_db_obj()
        resp = FindingResponse.model_validate(obj)
        assert isinstance(resp.id, str)
        assert isinstance(resp.scan_id, str)

    def test_status_field_present(self):
        obj = self._make_db_obj(status=FindingStatus.CONFIRMED)
        resp = FindingResponse.model_validate(obj)
        assert resp.status == FindingStatus.CONFIRMED

    def test_affected_asset_nullable(self):
        obj = self._make_db_obj(affected_asset=None)
        resp = FindingResponse.model_validate(obj)
        assert resp.affected_asset is None

    def test_references_default_empty_list(self):
        obj = self._make_db_obj(references=[])
        resp = FindingResponse.model_validate(obj)
        assert resp.references == []


# ── Reporting engine integration ──────────────────────────────────────────────

class TestReportingFromScanFindings:
    def _make_report_scan(self) -> ReportScan:
        return ReportScan(
            id=str(uuid.uuid4()),
            org_id=str(uuid.uuid4()),
            target_domain="mail.example.com",
            status="completed",
            created_at=datetime(2026, 11, 16, 10, 0, tzinfo=timezone.utc),
            started_at=datetime(2026, 11, 16, 10, 0, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 11, 16, 10, 5, tzinfo=timezone.utc),
            risk_score=55.0,
            finding_count=2,
            engine_runs=[],
        )

    def _make_report_finding(self, check_id: str, risk_level: str) -> ReportFinding:
        return ReportFinding(
            id=str(uuid.uuid4()),
            engine="dns_auth",
            check_id=check_id,
            title=f"Finding: {check_id}",
            description="...",
            risk_level=risk_level,
            confidence=0.9,
            affected_asset="mail.example.com",
            remediation="Fix it",
            evidence=[],
            references=[],
            status="open",
            cvss_score=None,
            created_at=datetime(2026, 11, 16, 10, 1, tzinfo=timezone.utc),
            last_seen_at=None,
        )

    def test_json_report_includes_risk_score(self):
        import json
        engine = ReportingEngine()
        scan = self._make_report_scan()
        findings = [self._make_report_finding("DA-SPF-ABSENT", "high")]
        content, _ = engine.generate(scan, findings, [], fmt="json")
        data = json.loads(content)
        assert data["scan"]["risk_score"] == 55.0

    def test_html_report_includes_all_findings(self):
        engine = ReportingEngine()
        scan = self._make_report_scan()
        findings = [
            self._make_report_finding("DA-SPF-ABSENT", "high"),
            self._make_report_finding("DA-DMARC-ABSENT", "medium"),
        ]
        content, _ = engine.generate(scan, findings, [], fmt="html")
        assert "DA-SPF-ABSENT" in content
        assert "DA-DMARC-ABSENT" in content

    def test_csv_report_all_findings_exported(self):
        import csv, io
        engine = ReportingEngine()
        scan = self._make_report_scan()
        findings = [self._make_report_finding(f"CHECK-{i}", "medium") for i in range(5)]
        content, _ = engine.generate(scan, findings, [], fmt="csv")
        rows = list(csv.reader(io.StringIO(content)))
        assert len(rows) == 6  # header + 5

    def test_report_type_full_contains_description(self):
        import json
        engine = ReportingEngine()
        scan = self._make_report_scan()
        findings = [self._make_report_finding("DA-SPF-ABSENT", "critical")]
        content, _ = engine.generate(scan, findings, [], report_type="full", fmt="json")
        data = json.loads(content)
        assert "description" in data["findings"][0]

    def test_report_with_chains(self):
        import json
        engine = ReportingEngine()
        scan = self._make_report_scan()
        chains = [
            {
                "rule_id": "RC-PHISHING-CHAIN",
                "title": "Phishing chain",
                "description": "...",
                "severity": "critical",
            }
        ]
        content, _ = engine.generate(scan, [], chains, fmt="json")
        data = json.loads(content)
        assert len(data["chains"]) == 1

    def test_posture_high_at_55(self):
        import json
        engine = ReportingEngine()
        scan = self._make_report_scan()  # risk_score=55
        content, _ = engine.generate(scan, [], [], fmt="json")
        data = json.loads(content)
        assert data["risk_summary"]["posture"] == "high"

    def test_posture_medium_at_30(self):
        import json
        engine = ReportingEngine()
        scan = self._make_report_scan()
        scan.risk_score = 30.0
        content, _ = engine.generate(scan, [], [], fmt="json")
        data = json.loads(content)
        assert data["risk_summary"]["posture"] == "medium"

    def test_posture_clean_at_zero(self):
        import json
        engine = ReportingEngine()
        scan = self._make_report_scan()
        scan.risk_score = 0.0
        content, _ = engine.generate(scan, [], [], fmt="json")
        data = json.loads(content)
        assert data["risk_summary"]["posture"] == "clean"

    def test_posture_unknown_when_none(self):
        import json
        engine = ReportingEngine()
        scan = self._make_report_scan()
        scan.risk_score = None
        content, _ = engine.generate(scan, [], [], fmt="json")
        data = json.loads(content)
        assert data["risk_summary"]["posture"] == "unknown"


# ── Migration field checks ────────────────────────────────────────────────────

class TestPhase5ModelFields:
    def test_scan_finding_has_status_attribute(self):
        from app.db.models.scan import ScanFinding
        # Check that the Python model defines the new columns
        assert hasattr(ScanFinding, "status")
        assert hasattr(ScanFinding, "affected_asset")
        assert hasattr(ScanFinding, "references")
        assert hasattr(ScanFinding, "last_seen_at")
        assert hasattr(ScanFinding, "cvss_score")

    def test_scan_has_risk_score_attribute(self):
        from app.db.models.scan import Scan
        assert hasattr(Scan, "risk_score")

    def test_finding_status_enum_imported_from_model(self):
        from app.db.models.scan import FindingStatus as FS
        assert FS.OPEN.value == "open"
        assert FS.RESOLVED.value == "resolved"
        assert FS.FALSE_POSITIVE.value == "false_positive"
