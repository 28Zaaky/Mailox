import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,98}[a-z0-9]$")


def _slugify(name: str) -> str:
    import re as _re
    slug = name.lower().strip()
    slug = _re.sub(r"[^a-z0-9\-]", "-", slug)
    slug = _re.sub(r"-+", "-", slug).strip("-")
    if len(slug) < 3:
        slug = slug + "-org"
    return slug[:100]


class CreateOrganizationRequest(BaseModel):
    name: str
    slug: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not 2 <= len(v) <= 255:
            raise ValueError("Name must be 2–255 characters")
        return v

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.lower().strip()
        if not _SLUG_RE.match(v):
            raise ValueError(
                "Slug must be 3–100 lowercase alphanumeric characters with hyphens "
                "(no leading/trailing hyphens)"
            )
        return v

    def get_slug(self) -> str:
        return self.slug if self.slug else _slugify(self.name)


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    is_active: bool
    created_at: Optional[datetime] = None
    # Role of the requesting user in this org (org_admin, analyst, pentester,
    # auditor), or "platform_admin" for a non-member platform admin. Lets the
    # frontend hide admin-only UI; the API still enforces permissions.
    current_user_role: Optional[str] = None

    @field_validator("id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> str:
        return str(v)


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        from app.db.models.organization import OrgRole
        valid = {r.value for r in OrgRole}
        if v not in valid:
            raise ValueError(f"Role must be one of: {', '.join(sorted(valid))}")
        return v


class MemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    user_id: str
    role: str
    is_active: bool
    email: Optional[str] = None
    full_name: Optional[str] = None
    joined_at: Optional[datetime] = None

    @field_validator("id", "org_id", "user_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> str:
        return str(v)


class OrgStatsResponse(BaseModel):
    total_scans: int
    active_scans: int
    open_critical: int
    open_high: int
    latest_scan_id: Optional[str] = None
    latest_risk_score: Optional[float] = None
    latest_risk_posture: Optional[str] = None


class UpdateOrgRequest(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not 2 <= len(v) <= 255:
            raise ValueError("Name must be 2–255 characters")
        return v


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: Optional[str] = None
    user_id: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[dict] = None
    ip_address: Optional[str] = None
    created_at: datetime

    @field_validator("id", "org_id", "user_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v) -> Optional[str]:
        return str(v) if v is not None else None


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int
