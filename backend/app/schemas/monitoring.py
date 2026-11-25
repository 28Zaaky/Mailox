import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator


class ScheduleCreate(BaseModel):
    profile_id: uuid.UUID
    cron_expression: str
    enabled: bool = True

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        parts = v.strip().split()
        if len(parts) not in (5, 6):
            raise ValueError("cron_expression must have 5 or 6 fields")
        return v.strip()


class ScheduleUpdate(BaseModel):
    cron_expression: Optional[str] = None
    enabled: Optional[bool] = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        parts = v.strip().split()
        if len(parts) not in (5, 6):
            raise ValueError("cron_expression must have 5 or 6 fields")
        return v.strip()


class MonitoringScheduleResponse(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    profile_id: uuid.UUID
    cron_expression: str
    enabled: bool
    next_run_at: Optional[datetime]
    last_run_at: Optional[datetime]
    last_scan_id: Optional[uuid.UUID]
    created_by: Optional[uuid.UUID]
    created_at: datetime

    model_config = {"from_attributes": True}


class MonitoringDeltaResponse(BaseModel):
    id: uuid.UUID
    schedule_id: uuid.UUID
    scan_id: uuid.UUID
    previous_scan_id: Optional[uuid.UUID]
    new_findings: int
    persistent_findings: int
    resolved_findings: int
    severity_changed: int
    computed_at: datetime

    model_config = {"from_attributes": True}
