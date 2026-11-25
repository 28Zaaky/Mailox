import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # Store SHA-256 hash of the raw token, never the raw token itself
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # All tokens in a family share the same family_id; reuse = revoke family
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        return self.expires_at < datetime.now(timezone.utc)

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired

    __table_args__ = (
        Index("ix_refresh_tokens_hash_unique", "token_hash", unique=True),
        Index("ix_refresh_tokens_family_id", "family_id"),
        Index("ix_refresh_tokens_user_id", "user_id"),
    )
