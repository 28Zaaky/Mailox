import enum
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base


class ProjectRole(str, enum.Enum):
    PROJECT_MANAGER = "project_manager"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    members: Mapped[List["ProjectMember"]] = relationship(
        "ProjectMember", back_populates="project", lazy="select", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_projects_org_id", "org_id"),)


class ProjectMember(Base):
    __tablename__ = "project_members"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(30), nullable=False, default="analyst")
    granted_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    project: Mapped["Project"] = relationship("Project", back_populates="members")

    __table_args__ = (Index("ix_project_members_user_id", "user_id"),)
