import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    asset_type: Mapped[str] = mapped_column(String(30), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    asset_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    project_links: Mapped[list["ProjectAsset"]] = relationship(
        "ProjectAsset", back_populates="asset", lazy="select"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "asset_type", "value", name="uq_assets_org_type_value"),
        Index("ix_assets_org_id", "org_id"),
        Index("ix_assets_asset_type", "asset_type"),
    )


class ProjectAsset(Base):
    __tablename__ = "project_assets"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    authorized_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    authorized_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="project_links")

    __table_args__ = (Index("ix_project_assets_project_id", "project_id"),)


class ScopeSnapshot(Base):
    __tablename__ = "scope_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    targets: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (Index("ix_scope_snapshots_scan_id", "scan_id"),)
