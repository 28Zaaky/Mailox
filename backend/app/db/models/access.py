"""SaaS access control: access requests, single-use invites, verified domains."""
import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AccessRequestStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class AccessRequest(Base):
    """A request for a SaaS account, submitted from the marketing site."""
    __tablename__ = "access_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    company: Mapped[str] = mapped_column(String(160), nullable=False)
    role: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    topic: Mapped[str] = mapped_column(String(20), nullable=False, default="access")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=AccessRequestStatus.PENDING.value)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        Index("ix_access_requests_status_created", "status", "created_at"),
        Index("ix_access_requests_email", "email"),
    )


class AccessInvite(Base):
    """Single-use invite that allows one account to be created for one email.

    Only the SHA-256 of the token is stored; the token itself is emailed once.
    """
    __tablename__ = "access_invites"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("access_requests.id", ondelete="SET NULL"), nullable=True
    )
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)

    __table_args__ = (Index("ix_access_invites_email", "email"),)


class VerifiedDomain(Base):
    """A domain an organization has proven it controls (DNS TXT challenge)."""
    __tablename__ = "verified_domains"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    token: Mapped[str] = mapped_column(String(64), nullable=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)

    __table_args__ = (
        UniqueConstraint("org_id", "domain", name="uq_verified_domains_org_domain"),
        Index("ix_verified_domains_org_id", "org_id"),
    )
