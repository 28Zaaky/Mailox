import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.db.models.base import Base, clip_text


class CanonicalFinding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=True,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    engine: Mapped[str] = mapped_column(String(60), nullable=False)
    check_id: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)

    @validates("title")
    def _clip_title(self, key: str, value):
        return clip_text(value, 500)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open")
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    first_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    history: Mapped[List["FindingStatusHistory"]] = relationship(
        "FindingStatusHistory", back_populates="canonical_finding", lazy="select"
    )

    __table_args__ = (
        Index("ix_findings_project", "project_id"),
        Index("ix_findings_fingerprint", "fingerprint"),
        Index("ix_findings_org_id", "org_id"),
    )


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_findings.id", ondelete="CASCADE"),
        nullable=True,
    )
    canonical_finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=True,
    )
    actor: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    prev_status: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    new_status: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    canonical_finding: Mapped[Optional["CanonicalFinding"]] = relationship(
        "CanonicalFinding", back_populates="history"
    )

    __table_args__ = (
        Index("ix_finding_status_history_canonical", "canonical_finding_id"),
        Index("ix_finding_status_history_scan_finding", "scan_finding_id"),
    )
