import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class MonitoringSchedule(Base):
    __tablename__ = "monitoring_schedules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    profile_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_profiles.id"), nullable=False
    )
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_monitoring_schedules_project_id", "project_id"),
        Index("ix_monitoring_schedules_next_run_at", "next_run_at"),
    )


class MonitoringDelta(Base):
    __tablename__ = "monitoring_deltas"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    schedule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("monitoring_schedules.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False
    )
    previous_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True
    )
    new_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    persistent_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resolved_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity_changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_monitoring_deltas_schedule_id", "schedule_id"),
    )
