"""
ExposedSecret — persistent finding from Module 07 (Credential Exposure Detection).

Secrets are NEVER stored in plaintext. Only masked_value is persisted.
Access is restricted by org_id — strict multi-tenant isolation.
"""
import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime, Enum as SQLEnum, Float, ForeignKey,
    Integer, String, Text, func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class SecretType(str, enum.Enum):
    SMTP_PASSWORD = "smtp_password"
    SMTP_USERNAME = "smtp_username"
    SMTP_DSN = "smtp_dsn"
    SMTP_HOST = "smtp_host"
    MAIL_API_KEY = "mail_api_key"
    GENERIC_PASSWORD = "generic_password"
    OAUTH_TOKEN = "oauth_token"


class SecretSourceType(str, enum.Enum):
    CONFIG_FILE = "config_file"
    ENV_FILE = "env_file"
    GIT_HISTORY = "git_history"
    ARCHIVE = "archive"
    SOURCE_CODE = "source_code"
    LOG_FILE = "log_file"
    BACKUP = "backup"


class ExposedSecretStatus(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


class ExposedSecret(Base):
    __tablename__ = "exposed_secrets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Optional: linked to a scan (for domain-contextualized secret scans)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    source_type: Mapped[str] = mapped_column(
        SQLEnum(SecretSourceType), nullable=False
    )
    source_name: Mapped[str] = mapped_column(String(512), nullable=False)
    source_path: Mapped[Optional[str]] = mapped_column(String(1024))

    secret_type: Mapped[str] = mapped_column(
        SQLEnum(SecretType), nullable=False
    )
    # masked value — e.g. "my***rd" — NEVER plaintext
    masked_value: Mapped[str] = mapped_column(String(512), nullable=False)
    # Risk level mirrors schemas.findings.RiskLevel values
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="high")

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    line_number: Mapped[Optional[int]] = mapped_column(Integer)
    # Surrounding code context — secrets masked within
    context_snippet: Mapped[Optional[str]] = mapped_column(Text)
    detection_rule: Mapped[Optional[str]] = mapped_column(String(256))

    status: Mapped[str] = mapped_column(
        SQLEnum(ExposedSecretStatus),
        nullable=False,
        default=ExposedSecretStatus.OPEN,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
