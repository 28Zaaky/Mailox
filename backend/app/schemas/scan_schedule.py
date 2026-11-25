import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, field_validator

_VALID_INTERVALS = {"daily", "weekly", "monthly"}


class ScanScheduleCreate(BaseModel):
    domain: str
    interval: Literal["daily", "weekly", "monthly"] = "weekly"

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or len(v) > 253:
            raise ValueError("domain must be 1–253 characters")
        return v


class ScanScheduleUpdate(BaseModel):
    enabled: Optional[bool] = None
    interval: Optional[Literal["daily", "weekly", "monthly"]] = None


class ScanScheduleResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    domain: str
    interval: str
    enabled: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    created_at: datetime
    created_by: Optional[uuid.UUID]

    model_config = {"from_attributes": True}
