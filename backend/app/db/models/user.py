import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    @property
    def sees_all_orgs(self) -> bool:
        """Whether this account may read every organization's data.

        Self-hosted: the platform admin owns the install, so yes.
        SaaS: the platform admin manages accounts and rights but never sees
        customers' assessments, findings or domains.
        """
        from app.core.config import settings
        return self.is_platform_admin and not settings.IS_SAAS

    # MFA
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_encrypted: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    mfa_last_used_totp: Mapped[Optional[str]] = mapped_column(String(6), nullable=True)
    mfa_backup_codes_encrypted: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    # Account lockout
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    org_memberships: Mapped[List["OrganizationMember"]] = relationship(
        "OrganizationMember", back_populates="user", lazy="select"
    )
    refresh_tokens: Mapped[List["RefreshToken"]] = relationship(
        "RefreshToken", back_populates="user", lazy="select"
    )

    __table_args__ = (
        Index("ix_users_email_unique", "email", unique=True),
    )
