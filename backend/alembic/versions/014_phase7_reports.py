"""Phase 7: reports persistence

Revision ID: 014
Revises: 013
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("report_type", sa.String(30), nullable=False),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column("title", sa.String(500), nullable=True),
        sa.Column("generated_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("storage_key", sa.String(500), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("metadata", JSONB(), server_default=sa.text("'{}'"), nullable=True),
    )
    op.create_index("ix_reports_org", "reports", ["org_id"])
    op.create_index("ix_reports_project", "reports", ["project_id"])
    op.create_index("ix_reports_scan", "reports", ["scan_id"])
    op.create_index("ix_reports_generated_at", "reports", ["generated_at"])


def downgrade() -> None:
    op.drop_index("ix_reports_generated_at", table_name="reports")
    op.drop_index("ix_reports_scan", table_name="reports")
    op.drop_index("ix_reports_project", table_name="reports")
    op.drop_index("ix_reports_org", table_name="reports")
    op.drop_table("reports")
