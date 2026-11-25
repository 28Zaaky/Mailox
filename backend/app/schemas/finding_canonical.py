import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class CanonicalFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    project_id: Optional[uuid.UUID] = None
    fingerprint: str
    engine: str
    check_id: str
    title: str
    status: str
    risk_level: str
    assigned_to: Optional[uuid.UUID] = None
    first_detected_at: datetime
    last_detected_at: datetime
    observation_count: int
    created_at: datetime


class CanonicalFindingUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[uuid.UUID] = None
    reason: Optional[str] = Field(None, max_length=500)
    comment: Optional[str] = Field(None, max_length=5000)


class CanonicalFindingSummary(BaseModel):
    total: int
    by_status: dict
    by_risk: dict


class FindingStatusHistoryEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_finding_id: Optional[uuid.UUID] = None
    canonical_finding_id: Optional[uuid.UUID] = None
    actor: Optional[uuid.UUID] = None
    prev_status: Optional[str] = None
    new_status: str
    reason: Optional[str] = None
    comment: Optional[str] = None
    changed_at: datetime
