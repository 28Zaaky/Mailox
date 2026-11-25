from datetime import date, datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AffectedRangeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    product_name: str
    introduced_version: Optional[str] = None
    fixed_version: Optional[str] = None
    last_affected_version: Optional[str] = None
    version_type: str
    version_constraints: list[str] = []


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_name: str
    source_record_id: Optional[str] = None
    source_url: Optional[str] = None
    retrieved_at: datetime


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cve_id: str
    title: Optional[str] = None
    description: Optional[str] = None
    published_at: Optional[datetime] = None
    severity: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    in_cisa_kev: bool
    exploit_available: bool
    relevance: str
    affected_product_count: int = 0


class VulnerabilityDetail(VulnerabilityOut):
    cvss_v3_vector: Optional[str] = None
    cwe_ids: list[str] = []
    references: list[str] = []
    exploit_references: list[str] = []
    kev_date_added: Optional[date] = None
    kev_required_action: Optional[str] = None
    kev_due_date: Optional[date] = None
    kev_ransomware_use: bool = False
    affected_ranges: list[AffectedRangeOut] = []
    sources: list[SourceOut] = []


class ProductOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    canonical_name: str
    vendor: Optional[str] = None
    category: str
    aliases: list[str] = []
    cve_count: int = 0


class SyncStatusOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_name: str
    last_sync_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    total_fetched: int
    records_added: int
    records_updated: int
    records_failed: int
    is_running: bool
    error_msg: Optional[str] = None


class SyncTriggerResponse(BaseModel):
    task_id: str
    source: str
    message: str


class VulnerabilityListResponse(BaseModel):
    items: list[VulnerabilityOut]
    total: int
    page: int
    per_page: int


class RelevancePatch(BaseModel):
    relevance: str
    reason: Optional[str] = None
