import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class OrgSettings(Base):
    __tablename__ = "org_settings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # API keys — stored encrypted via AES-256-GCM (crypto.py)
    github_token_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    intelx_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    nvd_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Scan preferences
    canary_email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    cred_probe_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    scan_timeout_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
