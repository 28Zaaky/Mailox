import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    asset_type: str
    value: str
    # ORM attribute is `asset_metadata` (`metadata` is reserved by SQLAlchemy's
    # declarative Base and resolves to the MetaData object).
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("asset_metadata", "metadata"),
    )
    first_seen_at: datetime
    last_seen_at: datetime


class ProjectAssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    project_id: uuid.UUID
    asset_id: uuid.UUID
    authorized: bool
    authorized_by: Optional[uuid.UUID]
    authorized_at: Optional[datetime]
    asset: AssetResponse


class AddScopeTargetRequest(BaseModel):
    asset_type: str
    value: str
    authorized: bool = True


class ScopeSnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    targets: list[dict[str, Any]]
    captured_at: datetime
