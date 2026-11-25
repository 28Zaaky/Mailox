import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.db.models.base import Base


class WebhookEvent(str, enum.Enum):
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    FINDING_CRITICAL = "finding.critical"
    FINDING_HIGH = "finding.high"


class WebhookConfig(Base):
    __tablename__ = "webhook_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    events: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    secret_enc: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)  # Fernet-encrypted
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    __table_args__ = (Index("ix_webhook_configs_org_id", "org_id"),)
