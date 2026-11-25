import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceType(str, Enum):
    DNS_RECORD = "dns_record"
    SMTP_RESPONSE = "smtp_response"
    TLS_CERTIFICATE = "tls_certificate"
    HTTP_RESPONSE = "http_response"
    HTTP_HEADER = "http_header"
    FILE_CONTENT = "file_content"
    ABSENCE = "absence"
    TIMEOUT = "timeout"
    ERROR = "error"
    ANALYSIS = "analysis"
    EXTERNAL_RECORD = "external_record"


class Evidence(BaseModel):
    type: EvidenceType
    observed_value: Optional[str] = None
    expected_value: Optional[str] = None
    source: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    technical_details: Optional[dict[str, Any]] = None


class Finding(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    engine: str
    check_id: str
    title: str
    description: str
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence]
    remediation: str
    affected_asset: Optional[str] = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    business_impact: Optional[str] = None
    references: list[str] = Field(default_factory=list)
