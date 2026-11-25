import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class OrgSettingsUpdate(BaseModel):
    github_token: Optional[str] = None       # plaintext in request, stored encrypted
    intelx_api_key: Optional[str] = None
    nvd_api_key: Optional[str] = None
    canary_email: Optional[str] = Field(None, max_length=254)
    cred_probe_enabled: Optional[bool] = None
    scan_timeout_seconds: Optional[int] = None


class OrgSettingsResponse(BaseModel):
    org_id: uuid.UUID
    # Never return raw API keys — return masked presence flags
    github_token_set: bool
    intelx_api_key_set: bool
    nvd_api_key_set: bool
    canary_email: Optional[str]
    cred_probe_enabled: Optional[bool]
    scan_timeout_seconds: Optional[int]
    updated_at: Optional[datetime]

    model_config = {"from_attributes": True}
