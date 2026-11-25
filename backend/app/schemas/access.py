import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class EditionInfo(BaseModel):
    edition: Literal["selfhosted", "saas"]
    # "local": no accounts, the app opens a session by itself (self-hosted tool)
    auth: Literal["local", "accounts"]
    registration: Literal["first_user", "open", "invite"]
    domain_verification_required: bool
    verify_prefix: str


class AccessRequestCreate(BaseModel):
    """Body sent by the marketing site's contact form."""
    topic: Literal["access", "demo", "contact"] = "access"
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    company: str = Field(min_length=1, max_length=160)
    role: Optional[str] = Field(default=None, max_length=120)
    message: Optional[str] = Field(default=None, max_length=2000)
    website: Optional[str] = Field(default=None, max_length=200)  # honeypot: humans leave it empty


class AccessRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    name: str
    company: str
    role: Optional[str]
    message: Optional[str]
    topic: str
    status: str
    ip_address: Optional[str]
    created_at: datetime
    reviewed_at: Optional[datetime]


class InviteCreate(BaseModel):
    email: EmailStr
    name: str = Field(default="", max_length=120)


class InviteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    request_id: Optional[uuid.UUID]
    expires_at: datetime
    used_at: Optional[datetime]
    revoked_at: Optional[datetime]
    created_at: datetime


class InviteIssued(InviteOut):
    # Only filled when the email could not be sent (no SMTP, or delivery refused),
    # so the admin can pass the link on
    invite_url: Optional[str] = None
    email_sent: bool


class InviteLookup(BaseModel):
    email: Optional[str]
    valid: bool


class AdminUserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: Optional[str]
    is_active: bool
    is_platform_admin: bool
    created_at: datetime


class VerifiedDomainCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


class VerifiedDomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    domain: str
    token: str
    verified_at: Optional[datetime]
    last_checked_at: Optional[datetime]
    created_at: datetime
    txt_name: str = ""
    txt_value: str = ""


class VerifyResult(BaseModel):
    domain: VerifiedDomainOut
    verified: bool
    txt_found: list[str]


class AdminOrgRef(BaseModel):
    id: uuid.UUID
    name: str
    role: str


class AdminUserDetail(BaseModel):
    id: uuid.UUID
    email: str
    full_name: Optional[str]
    is_active: bool
    is_platform_admin: bool
    mfa_enabled: bool
    locked_until: Optional[datetime]
    created_at: datetime
    orgs: list[AdminOrgRef]


class AdminFlag(BaseModel):
    enabled: bool


class AdminOrgMember(BaseModel):
    email: str
    role: str


class AdminOrgOut(BaseModel):
    """Organization metadata only: no scan targets, findings or domain names."""
    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    created_at: datetime
    daily_scan_quota: Optional[int]
    effective_daily_scan_quota: int
    offensive_modules_allowed: bool
    members: list[AdminOrgMember]
    scans_24h: int
    scans_30d: int
    verified_domains: int


class AdminOrgUpdate(BaseModel):
    # Omit a field to leave it unchanged; daily_scan_quota=null restores the default
    daily_scan_quota: Optional[int] = Field(default=None, ge=0, le=10000)
    offensive_modules_allowed: Optional[bool] = None
    is_active: Optional[bool] = None


class EmailLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    recipient: str
    subject: str
    template: str
    status: str
    error_message: Optional[str]
    created_at: datetime
