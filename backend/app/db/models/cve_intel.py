import enum
import uuid
from datetime import date, datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean, Date, DateTime, Float, ForeignKey,
    Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ProductCategory(str, enum.Enum):
    SMTP = "smtp"
    WEBMAIL = "webmail"
    IMAP_POP3 = "imap_pop3"
    DNS_AUTH = "dns_auth"
    TLS_CRYPTO = "tls_crypto"
    PHP = "php"
    CMS = "cms"
    ANTISPAM = "antispam"
    WEB_SERVER = "web_server"
    OS = "os"
    DATABASE = "database"
    EMAIL_LIBRARY = "email_library"
    MAIL_GATEWAY = "mail_gateway"
    HOSTING_PANEL = "hosting_panel"
    EMAIL_PROVIDER = "email_provider"
    CONTAINER = "container"
    RUNTIME = "runtime"
    OTHER = "other"


class VulnRelevance(str, enum.Enum):
    DIRECT = "direct"
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    DEPENDENCY = "dependency"
    ENVIRONMENTAL = "environmental"
    INDIRECT = "indirect"
    NOT_RELEVANT = "not_relevant"


class VulnStatus(str, enum.Enum):
    ACTIVE = "active"
    WITHDRAWN = "withdrawn"
    DISPUTED = "disputed"
    REJECTED = "rejected"


class VersionType(str, enum.Enum):
    SEMVER = "semver"
    DEBIAN = "debian"
    RPM = "rpm"
    WINDOWS_BUILD = "windows_build"
    NUMERIC = "numeric"
    CUSTOM = "custom"


class MatchStatus(str, enum.Enum):
    CONFIRMED_AFFECTED = "confirmed_affected"
    LIKELY_AFFECTED = "likely_affected"
    POTENTIALLY_AFFECTED = "potentially_affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNKNOWN_VERSION = "unknown_version"
    PRODUCT_MATCH_ONLY = "product_match_only"
    NOT_ENOUGH_EVIDENCE = "not_enough_evidence"


# ---------------------------------------------------------------------------
# CveProduct
# ---------------------------------------------------------------------------

class CveProduct(Base, TimestampMixin):
    __tablename__ = "cve_products"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    canonical_name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    vendor: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    category: Mapped[str] = mapped_column(
        String(64), nullable=False, default=ProductCategory.OTHER.value
    )
    product_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ecosystem: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    homepage: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    aliases: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True, default=list)
    cpe_identifiers: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True, default=list)
    purl_identifiers: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    affected_ranges: Mapped[List["CveAffectedRange"]] = relationship(
        "CveAffectedRange", back_populates="product", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_cve_products_canonical_name", "canonical_name"),
        Index("ix_cve_products_category", "category"),
    )


# ---------------------------------------------------------------------------
# CveVulnerability
# ---------------------------------------------------------------------------

class CveVulnerability(Base, TimestampMixin):
    __tablename__ = "cve_vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    title: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    published_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    modified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=VulnStatus.ACTIVE.value
    )

    # CVSS
    cvss_v3_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    cvss_v4_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_v4_vector: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # CWE / References
    cwe_ids: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True, default=list)
    references: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True, default=list)

    # Exploit intelligence
    exploit_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exploit_maturity: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    exploit_references: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True, default=list)

    # CISA KEV
    in_cisa_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_date_added: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    kev_required_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    kev_due_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    kev_ransomware_use: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relevance classification
    relevance: Mapped[str] = mapped_column(
        String(32), nullable=False, default=VulnRelevance.INDIRECT.value
    )
    relevance_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    relevance_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    relevance_manual: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Source confidence
    source_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.9)

    # Relationships
    affected_ranges: Mapped[List["CveAffectedRange"]] = relationship(
        "CveAffectedRange", back_populates="vulnerability", cascade="all, delete-orphan"
    )
    sources: Mapped[List["CveSource"]] = relationship(
        "CveSource", back_populates="vulnerability", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_cve_vulnerabilities_cve_id", "cve_id"),
        Index("ix_cve_vulnerabilities_severity", "severity"),
        Index("ix_cve_vulnerabilities_relevance", "relevance"),
        Index("ix_cve_vulnerabilities_in_cisa_kev", "in_cisa_kev"),
        Index("ix_cve_vulnerabilities_published_at", "published_at"),
        Index("ix_cve_vulnerabilities_status", "status"),
    )


# ---------------------------------------------------------------------------
# CveAffectedRange
# ---------------------------------------------------------------------------

class CveAffectedRange(Base):
    __tablename__ = "cve_affected_ranges"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    product_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_products.id", ondelete="CASCADE"),
        nullable=False,
    )
    introduced_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    last_affected_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    version_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default=VersionType.SEMVER.value
    )
    version_constraints: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=list
    )
    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    range_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.9)

    vulnerability: Mapped["CveVulnerability"] = relationship(
        "CveVulnerability", back_populates="affected_ranges"
    )
    product: Mapped["CveProduct"] = relationship(
        "CveProduct", back_populates="affected_ranges"
    )

    __table_args__ = (
        Index("ix_cve_affected_ranges_vuln_id", "vulnerability_id"),
        Index("ix_cve_affected_ranges_product_id", "product_id"),
    )


# ---------------------------------------------------------------------------
# CveSource
# ---------------------------------------------------------------------------

class CveSource(Base):
    __tablename__ = "cve_sources"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_name: Mapped[str] = mapped_column(String(64), nullable=False)
    source_record_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    source_modified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    raw_record_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_revision: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    vulnerability: Mapped["CveVulnerability"] = relationship(
        "CveVulnerability", back_populates="sources"
    )

    __table_args__ = (
        UniqueConstraint("vulnerability_id", "source_name", name="uq_cve_source_vuln_source"),
        Index("ix_cve_sources_vulnerability_id", "vulnerability_id"),
        Index("ix_cve_sources_source_name", "source_name"),
    )


# ---------------------------------------------------------------------------
# CveSyncStatus  (one row per source)
# ---------------------------------------------------------------------------

class CveSyncStatus(Base):
    __tablename__ = "cve_sync_status"

    source_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_success_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    total_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_added: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_msg: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_running: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sync_cursor: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
