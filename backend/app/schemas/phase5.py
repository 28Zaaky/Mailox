"""
API schemas: findings management and reports.
"""
import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models.scan import FindingState, FindingStatus, RiskLevel


# ---------------------------------------------------------------------------
# Findings management
# ---------------------------------------------------------------------------

class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    engine: str
    check_id: str
    title: str
    description: str
    risk_level: RiskLevel
    confidence: float
    affected_asset: Optional[str] = None
    status: FindingStatus
    cvss_score: Optional[float] = None
    evidence: Any = None
    remediation: str
    references: list = Field(default_factory=list)
    created_at: datetime
    last_seen_at: Optional[datetime] = None
    fingerprint: Optional[str] = None
    status_changed_at: Optional[datetime] = None
    status_changed_by: Optional[str] = None
    # State workflow
    state: str = "open"
    state_note: Optional[str] = None
    state_updated_at: Optional[datetime] = None

    @field_validator("id", "scan_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> str:
        return str(v)

    @field_validator("status_changed_by", mode="before")
    @classmethod
    def coerce_status_changed_by(cls, v) -> Optional[str]:
        return str(v) if v is not None else None


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class FindingStateUpdate(BaseModel):
    state: FindingState
    note: Optional[str] = None


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    page_size: int


class FindingSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_engine: dict[str, int]
    open_critical: int
    open_high: int


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportRequest(BaseModel):
    report_type: str = Field(
        "full",
        pattern="^(executive|technical|full)$",
    )
    format: str = Field(
        "json",
        pattern="^(json|html|csv)$",
    )
