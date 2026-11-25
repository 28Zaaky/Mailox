import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


VALID_ENGINES = {"dns_auth", "smtp_discovery", "webmail", "vuln_intel"}


class ProfileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    project_id: Optional[uuid.UUID] = None
    engines: List[str] = Field(
        default=["dns_auth", "smtp_discovery", "webmail", "vuln_intel"]
    )
    config: dict = Field(default_factory=dict)
    time_limit_seconds: int = Field(default=3600, ge=60, le=86400)

    def validate_engines(self) -> List[str]:
        invalid = set(self.engines) - VALID_ENGINES
        if invalid:
            raise ValueError(f"Unknown engines: {invalid}")
        return self.engines


class ProfileUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    engines: Optional[List[str]] = None
    config: Optional[dict] = None
    time_limit_seconds: Optional[int] = Field(None, ge=60, le=86400)


class ProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: Optional[uuid.UUID]
    project_id: Optional[uuid.UUID]
    name: str
    engines: List[str]
    config: dict
    time_limit_seconds: int
    created_by: Optional[uuid.UUID]
    created_at: datetime
    is_builtin: bool
