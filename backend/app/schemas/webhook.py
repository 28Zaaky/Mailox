import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.db.models.webhook import WebhookEvent

_VALID_EVENTS = {e.value for e in WebhookEvent}


class WebhookCreate(BaseModel):
    url: str
    events: list[str]
    secret: Optional[str] = Field(None, max_length=512)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        if len(v) > 2048:
            raise ValueError("url must be ≤ 2048 characters")
        return v

    @field_validator("events")
    @classmethod
    def validate_events(cls, v: list[str]) -> list[str]:
        for event in v:
            if event not in _VALID_EVENTS:
                raise ValueError(
                    f"unknown event '{event}'; valid: {sorted(_VALID_EVENTS)}"
                )
        if not v:
            raise ValueError("events must contain at least one entry")
        return v


class WebhookUpdate(BaseModel):
    url: Optional[str] = None
    events: Optional[list[str]] = None
    enabled: Optional[bool] = None
    secret: Optional[str] = Field(None, max_length=512)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        if len(v) > 2048:
            raise ValueError("url must be ≤ 2048 characters")
        return v

    @field_validator("events")
    @classmethod
    def validate_events(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return v
        for event in v:
            if event not in _VALID_EVENTS:
                raise ValueError(
                    f"unknown event '{event}'; valid: {sorted(_VALID_EVENTS)}"
                )
        if not v:
            raise ValueError("events must contain at least one entry")
        return v


class WebhookResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    url: str
    events: list[str]
    enabled: bool
    created_at: datetime
    last_triggered_at: Optional[datetime]
    last_status_code: Optional[int]
    # secret is intentionally excluded from responses

    model_config = {"from_attributes": True}
