import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    project_id: Optional[uuid.UUID] = None
    scan_id: Optional[uuid.UUID] = None
    report_type: str
    format: str
    title: Optional[str] = None
    generated_by: Optional[uuid.UUID] = None
    generated_at: datetime
    size_bytes: Optional[int] = None
    # storage_key intentionally omitted — internal detail


class GenerateReportRequest(BaseModel):
    scan_id: uuid.UUID
    report_type: str = "full"   # executive|technical|full
    format: str = "json"        # json|html|csv
    project_id: Optional[uuid.UUID] = None
    title: Optional[str] = None


class ProjectReportRequest(BaseModel):
    report_type: str = "project"
    format: str = "json"
    include_scan_ids: Optional[List[uuid.UUID]] = None
    title: Optional[str] = None
