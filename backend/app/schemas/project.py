import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, field_validator


class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not 2 <= len(v) <= 255:
            raise ValueError("Name must be 2–255 characters")
        return v


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not 2 <= len(v) <= 255:
            raise ValueError("Name must be 2–255 characters")
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if v not in {"active", "archived", "closed"}:
            raise ValueError("Status must be one of: active, archived, closed")
        return v


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    name: str
    description: Optional[str] = None
    status: str
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    @field_validator("id", "org_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> str:
        return str(v)

    @field_validator("created_by", mode="before")
    @classmethod
    def coerce_created_by(cls, v) -> Optional[str]:
        return str(v) if v is not None else None


class ProjectMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    project_id: str
    user_id: str
    role: str
    granted_at: datetime

    @field_validator("project_id", "user_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> str:
        return str(v)


class AddMemberRequest(BaseModel):
    user_id: uuid.UUID  # typed: a non-UUID is a 422, not a ValueError -> 500
    role: str = "analyst"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        valid = {"project_manager", "analyst", "auditor", "viewer"}
        if v not in valid:
            raise ValueError(f"Role must be one of: {', '.join(sorted(valid))}")
        return v
