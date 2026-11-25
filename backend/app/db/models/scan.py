import enum
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer,
    String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.models.base import Base, clip_text


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RiskLevel(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    ACCEPTED_RISK = "accepted_risk"
    IN_REMEDIATION = "in_remediation"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class FindingState(str, enum.Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class EngineRunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_domain: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False, default=ScanStatus.PENDING
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_msg: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    quota_tokens_used: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    current_engine: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    progress_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Worker lease / fencing token
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    worker_lease_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Aggregate risk score from correlation engine (0-100)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="SET NULL"),
        nullable=True,
    )

    profile_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )

    monitoring_schedule_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitoring_schedules.id", ondelete="SET NULL"),
        nullable=True,
    )

    findings: Mapped[List["ScanFinding"]] = relationship(
        "ScanFinding", back_populates="scan", lazy="select",
        passive_deletes=True,
    )
    engine_runs: Mapped[List["ScanEngineRun"]] = relationship(
        "ScanEngineRun", back_populates="scan", lazy="select",
        passive_deletes=True,
    )

    __table_args__ = (
        Index("ix_scans_org_id", "org_id"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_created_at", "created_at"),
        Index("ix_scans_org_created", "org_id", "created_at"),
        # BUG-07 fix: unique partial index — migration 004 creates it; keep the
        # non-unique definition here only for pre-004 compat (Alembic autogenerate
        # would diff it, but we never use autogenerate in this project).
        Index("ix_scans_idempotency", "org_id", "idempotency_key"),
        Index("ix_scans_project_id", "project_id"),
        Index("ix_scans_profile_id", "profile_id"),
        Index("ix_scans_monitoring_schedule_id", "monitoring_schedule_id"),
    )

    @property
    def finding_count(self) -> int:
        return len(self.findings) if self.findings else 0


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    engine: Mapped[str] = mapped_column(String(50), nullable=False)
    check_id: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(
        Enum(RiskLevel, name="risk_level", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="findingstatus", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=FindingStatus.OPEN,
    )
    affected_asset: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    references: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Every persistence path (worker, secrets upload, tests) goes through the ORM:
    # truncate here instead of at each call site.
    @validates("title", "affected_asset")
    def _clip_varchar(self, key: str, value):
        return clip_text(value, 255)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Deduplication fingerprint + status audit trail
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status_changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status_changed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    canonical_finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
    )

    # State workflow (open / resolved / accepted_risk / false_positive)
    state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open", server_default="open"
    )
    state_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    state_updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("ix_scan_findings_scan_id", "scan_id"),
        Index("ix_scan_findings_risk_level", "risk_level"),
        Index("ix_scan_findings_engine", "engine"),
        Index("ix_scan_findings_status", "status"),
        Index("ix_scan_findings_fingerprint", "fingerprint"),
        Index("ix_scan_findings_status_changed_by", "status_changed_by"),
        Index("ix_scan_findings_canonical_finding_id", "canonical_finding_id"),
    )


class ScanOutbox(Base):
    """Transactional outbox: at-least-once delivery guarantee for Celery scan tasks.

    Provides at-least-once (not exactly-once) delivery. Duplicate dispatches are
    safe because the worker uses an atomic lease acquisition (UPDATE WHERE status=QUEUED
    RETURNING) — only the first worker to acquire the lease processes the scan.
    """

    __tablename__ = "scan_outbox"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    published_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Safe concurrent recovery
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (Index("ix_scan_outbox_published", "published"),)


class ScanEngineRun(Base):
    """Per-engine execution record for a scan attempt."""

    __tablename__ = "scan_engine_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    engine: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_msg: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="engine_runs")

    __table_args__ = (
        Index("ix_engine_runs_scan_id", "scan_id"),
        UniqueConstraint(
            "scan_id", "attempt_number", "engine",
            name="uq_engine_runs_scan_attempt_engine",
        ),
    )
