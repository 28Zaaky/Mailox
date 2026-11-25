import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    report_type: Mapped[str] = mapped_column(String(30), nullable=False)  # executive|technical|full|project
    format: Mapped[str] = mapped_column(String(10), nullable=False)       # json|html|csv|pdf
    title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    generated_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    storage_key: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer(), nullable=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB(), nullable=True, default=dict)

    # Relationships
    organization = relationship("Organization", foreign_keys=[org_id])
    project = relationship("Project", foreign_keys=[project_id])
    scan = relationship("Scan", foreign_keys=[scan_id])
    generator = relationship("User", foreign_keys=[generated_by])
