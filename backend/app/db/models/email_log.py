"""Email log model for tracking all outbound emails."""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Index, String, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class EmailLog(Base):
    __tablename__ = "email_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    template: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # sent, failed, pending
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        Index("ix_email_logs_recipient", "recipient"),
        Index("ix_email_logs_created_at", "created_at"),
        Index("ix_email_logs_status", "status"),
    )
