"""CVE Intelligence Platform — products, vulnerabilities, affected ranges, sources, sync status

Revision ID: 016
Revises: 015
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── cve_products ─────────────────────────────────────────────────────────
    op.create_table(
        "cve_products",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_name", sa.String(256), nullable=False),
        sa.Column("vendor", sa.String(256), nullable=True),
        sa.Column("category", sa.String(64), nullable=False, server_default="other"),
        sa.Column("product_type", sa.String(64), nullable=True),
        sa.Column("ecosystem", sa.String(64), nullable=True),
        sa.Column("homepage", sa.String(512), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("aliases", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("cpe_identifiers", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("purl_identifiers", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("canonical_name"),
    )
    op.create_index("ix_cve_products_canonical_name", "cve_products", ["canonical_name"])
    op.create_index("ix_cve_products_category", "cve_products", ["category"])

    # ── cve_vulnerabilities ───────────────────────────────────────────────────
    op.create_table(
        "cve_vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("cvss_v3_score", sa.Float(), nullable=True),
        sa.Column("cvss_v3_vector", sa.String(256), nullable=True),
        sa.Column("cvss_v4_score", sa.Float(), nullable=True),
        sa.Column("cvss_v4_vector", sa.String(256), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("cwe_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("exploit_available", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("exploit_maturity", sa.String(64), nullable=True),
        sa.Column("exploit_references", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("in_cisa_kev", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("kev_date_added", sa.Date(), nullable=True),
        sa.Column("kev_required_action", sa.Text, nullable=True),
        sa.Column("kev_due_date", sa.Date(), nullable=True),
        sa.Column("kev_ransomware_use", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("relevance", sa.String(32), nullable=False, server_default="indirect"),
        sa.Column("relevance_reason", sa.Text, nullable=True),
        sa.Column("relevance_confidence", sa.Float(), nullable=False, server_default=sa.text("0.5")),
        sa.Column("relevance_manual", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("source_confidence", sa.Float(), nullable=False, server_default=sa.text("0.9")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_index("ix_cve_vulnerabilities_cve_id", "cve_vulnerabilities", ["cve_id"])
    op.create_index("ix_cve_vulnerabilities_severity", "cve_vulnerabilities", ["severity"])
    op.create_index("ix_cve_vulnerabilities_relevance", "cve_vulnerabilities", ["relevance"])
    op.create_index("ix_cve_vulnerabilities_in_cisa_kev", "cve_vulnerabilities", ["in_cisa_kev"])
    op.create_index("ix_cve_vulnerabilities_published_at", "cve_vulnerabilities", ["published_at"])
    op.create_index("ix_cve_vulnerabilities_status", "cve_vulnerabilities", ["status"])

    # ── cve_affected_ranges ───────────────────────────────────────────────────
    op.create_table(
        "cve_affected_ranges",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vulnerability_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("product_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("introduced_version", sa.String(128), nullable=True),
        sa.Column("fixed_version", sa.String(128), nullable=True),
        sa.Column("last_affected_version", sa.String(128), nullable=True),
        sa.Column("version_type", sa.String(32), nullable=False, server_default="semver"),
        sa.Column("version_constraints", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("source", sa.String(64), nullable=True),
        sa.Column("range_confidence", sa.Float(), nullable=False, server_default=sa.text("0.9")),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["cve_vulnerabilities.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["product_id"], ["cve_products.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cve_affected_ranges_vuln_id", "cve_affected_ranges", ["vulnerability_id"])
    op.create_index("ix_cve_affected_ranges_product_id", "cve_affected_ranges", ["product_id"])

    # ── cve_sources ───────────────────────────────────────────────────────────
    op.create_table(
        "cve_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vulnerability_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_name", sa.String(64), nullable=False),
        sa.Column("source_record_id", sa.String(256), nullable=True),
        sa.Column("source_url", sa.String(1024), nullable=True),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_record_hash", sa.String(64), nullable=True),
        sa.Column("source_revision", sa.String(128), nullable=True),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["cve_vulnerabilities.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("vulnerability_id", "source_name", name="uq_cve_source_vuln_source"),
    )
    op.create_index("ix_cve_sources_vulnerability_id", "cve_sources", ["vulnerability_id"])
    op.create_index("ix_cve_sources_source_name", "cve_sources", ["source_name"])

    # ── cve_sync_status ───────────────────────────────────────────────────────
    op.create_table(
        "cve_sync_status",
        sa.Column("source_name", sa.String(64), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_fetched", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("records_added", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("records_updated", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("records_skipped", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("records_failed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_msg", sa.Text, nullable=True),
        sa.Column("is_running", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("sync_cursor", sa.Text, nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("source_name"),
    )

    # Seed sync status rows — one per source
    op.execute(
        """
        INSERT INTO cve_sync_status (source_name, total_fetched, records_added, records_updated,
            records_skipped, records_failed, is_running, updated_at)
        VALUES
            ('STATIC_SEED', 0, 0, 0, 0, 0, false, NOW()),
            ('NVD', 0, 0, 0, 0, 0, false, NOW()),
            ('CISA_KEV', 0, 0, 0, 0, 0, false, NOW()),
            ('OSV', 0, 0, 0, 0, 0, false, NOW()),
            ('GITHUB_ADVISORY', 0, 0, 0, 0, 0, false, NOW())
        """
    )


def downgrade() -> None:
    op.drop_table("cve_sync_status")
    op.drop_index("ix_cve_sources_source_name", table_name="cve_sources")
    op.drop_index("ix_cve_sources_vulnerability_id", table_name="cve_sources")
    op.drop_table("cve_sources")
    op.drop_index("ix_cve_affected_ranges_product_id", table_name="cve_affected_ranges")
    op.drop_index("ix_cve_affected_ranges_vuln_id", table_name="cve_affected_ranges")
    op.drop_table("cve_affected_ranges")
    op.drop_index("ix_cve_vulnerabilities_status", table_name="cve_vulnerabilities")
    op.drop_index("ix_cve_vulnerabilities_published_at", table_name="cve_vulnerabilities")
    op.drop_index("ix_cve_vulnerabilities_in_cisa_kev", table_name="cve_vulnerabilities")
    op.drop_index("ix_cve_vulnerabilities_relevance", table_name="cve_vulnerabilities")
    op.drop_index("ix_cve_vulnerabilities_severity", table_name="cve_vulnerabilities")
    op.drop_index("ix_cve_vulnerabilities_cve_id", table_name="cve_vulnerabilities")
    op.drop_table("cve_vulnerabilities")
    op.drop_index("ix_cve_products_category", table_name="cve_products")
    op.drop_index("ix_cve_products_canonical_name", table_name="cve_products")
    op.drop_table("cve_products")
