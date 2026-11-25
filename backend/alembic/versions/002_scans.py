"""Add scans and scan_findings tables

Revision ID: 002
Revises: 001
Create Date: 2026-11-13
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── scans ─────────────────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_domain", sa.String(253), nullable=False),
        sa.Column(
            "status",
            sa.Enum("pending", "running", "completed", "failed", "cancelled", name="scan_status"),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("quota_tokens_used", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_scans_org_id", "scans", ["org_id"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])
    op.create_index("ix_scans_org_created", "scans", ["org_id", "created_at"])

    # ── scan_findings ─────────────────────────────────────────────────────────
    op.create_table(
        "scan_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("engine", sa.String(50), nullable=False),
        sa.Column("check_id", sa.String(50), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "risk_level",
            sa.Enum("info", "low", "medium", "high", "critical", name="risk_level"),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_findings_scan_id", "scan_findings", ["scan_id"])
    op.create_index("ix_scan_findings_risk_level", "scan_findings", ["risk_level"])
    op.create_index("ix_scan_findings_engine", "scan_findings", ["engine"])


def downgrade() -> None:
    op.drop_table("scan_findings")
    op.drop_table("scans")
    op.execute("DROP TYPE IF EXISTS risk_level")
    op.execute("DROP TYPE IF EXISTS scan_status")
