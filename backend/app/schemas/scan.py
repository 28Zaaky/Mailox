import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.findings import Finding, RiskLevel

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class ScanStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanCreate(BaseModel):
    target_domain: str
    project_id: Optional[uuid.UUID] = None
    profile_id: Optional[uuid.UUID] = None

    @field_validator("target_domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) > 253:
            raise ValueError("Domain name too long (max 253 characters)")
        if not _DOMAIN_RE.match(v):
            raise ValueError("Invalid domain name")
        return v


class ScanFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    engine: str
    check_id: str
    title: str
    description: str
    risk_level: RiskLevel
    confidence: float
    evidence: Any
    remediation: str
    created_at: datetime
    affected_asset: Optional[str] = None
    status: Optional[str] = None
    cvss_score: Optional[float] = None
    references: list = Field(default_factory=list)
    last_seen_at: Optional[datetime] = None

    @field_validator("id", "scan_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> str:
        return str(v)


class EngineRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    attempt_number: int
    engine: str
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    finding_count: int = 0
    error_msg: Optional[str] = None

    @field_validator("id", "scan_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> str:
        return str(v)


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    target_domain: str
    status: ScanStatus
    created_by: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_msg: Optional[str] = None
    finding_count: int = 0
    risk_score: Optional[float] = None
    progress_pct: int = 0
    current_engine: Optional[str] = None
    attempt_number: int = 0
    project_id: Optional[str] = None

    @field_validator("id", "org_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> str:
        return str(v)

    @field_validator("created_by", "project_id", mode="before")
    @classmethod
    def coerce_created_by(cls, v) -> Optional[str]:
        return str(v) if v is not None else None


class ScanWithFindingsResponse(ScanResponse):
    findings: List[ScanFindingResponse] = Field(default_factory=list)
    engine_runs: List[EngineRunResponse] = Field(default_factory=list)


class MXRecord(BaseModel):
    priority: int
    hostname: str


class WebmailHost(BaseModel):
    host: str
    product: str
    version: Optional[str] = None


class SMTPHost(BaseModel):
    host: str
    port: int


class ScanAssetsResponse(BaseModel):
    mx_records: List[MXRecord]
    webmail_hosts: List[WebmailHost]
    smtp_hosts: List[SMTPHost]
