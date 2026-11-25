import enum
import uuid
from typing import List, Optional

from sqlalchemy import Boolean, Enum, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin


class OrgRole(str, enum.Enum):
    ORG_ADMIN = "org_admin"
    SECURITY_ANALYST = "analyst"
    PENTESTER = "pentester"
    AUDITOR = "auditor"


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "platform_admin": {"*"},
    OrgRole.ORG_ADMIN: {
        "org:read", "org:write", "org:manage_members",
        "project:read", "project:write",
        "assessment:read", "assessment:write",
        "finding:read", "finding:write",
        "report:read", "report:write",
    },
    OrgRole.SECURITY_ANALYST: {
        "org:read",
        "project:read", "project:write",
        "assessment:read", "assessment:write",
        "finding:read", "finding:write",
        "report:read",
    },
    OrgRole.PENTESTER: {
        "org:read",
        "project:read",
        "assessment:read", "assessment:write",
        "finding:read", "finding:write",
    },
    OrgRole.AUDITOR: {
        "org:read",
        "project:read",
        "assessment:read",
        "finding:read",
        "report:read",
    },
}


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    pentest_config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    # Set by a platform admin. daily_scan_quota NULL = service default.
    daily_scan_quota: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    offensive_modules_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")

    members: Mapped[List["OrganizationMember"]] = relationship(
        "OrganizationMember", back_populates="organization", lazy="select"
    )

    __table_args__ = (Index("ix_organizations_slug_unique", "slug", unique=True),)


class OrganizationMember(Base, TimestampMixin):
    __tablename__ = "organization_members"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[OrgRole] = mapped_column(
        Enum(OrgRole, name="org_role", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="members"
    )
    user: Mapped["User"] = relationship("User", back_populates="org_memberships")

    __table_args__ = (
        Index("ix_org_members_org_user_unique", "org_id", "user_id", unique=True),
        Index("ix_org_members_user_id", "user_id"),
    )
