"""
API schemas: webmail, CVE, and secrets responses.
"""
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.db.models.secrets import ExposedSecretStatus, SecretSourceType, SecretType


# ---------------------------------------------------------------------------
# Module 05 — Webmail
# ---------------------------------------------------------------------------

class WebmailEndpointOut(BaseModel):
    url: str
    product: str
    version: Optional[str] = None
    confidence: float
    status_code: int
    fingerprint_signals: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Module 06 — CVE / Vulnerability Intelligence
# ---------------------------------------------------------------------------

class CVEEntryOut(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    severity: str
    in_cisa_kev: bool = False
    exploit_available: bool = False
    published_date: Optional[str] = None
    references: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class SoftwareMatchOut(BaseModel):
    product: str
    version: Optional[str] = None
    confidence: str
    cves: list[CVEEntryOut] = Field(default_factory=list)

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Module 07 — Secrets
# ---------------------------------------------------------------------------

class ExposedSecretOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    source_type: SecretSourceType
    source_name: str
    source_path: Optional[str] = None
    secret_type: SecretType
    masked_value: str
    risk_level: str
    confidence: float
    line_number: Optional[int] = None
    context_snippet: Optional[str] = None
    detection_rule: Optional[str] = None
    status: ExposedSecretStatus
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SecretScanResponse(BaseModel):
    """Response from POST /secrets/scan"""
    total_hits: int
    files_scanned: int
    secrets: list[ExposedSecretOut] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SecretStatusUpdate(BaseModel):
    """PATCH /secrets/{id}/status"""
    status: ExposedSecretStatus


class SecretListResponse(BaseModel):
    items: list[ExposedSecretOut]
    total: int
    page: int
    page_size: int
