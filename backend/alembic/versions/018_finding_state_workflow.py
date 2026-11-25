"""Finding state workflow — open / resolved / accepted_risk / false_positive

Revision ID: 018
Revises: 017
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_findings",
        sa.Column("state", sa.String(32), nullable=False, server_default="open"),
    )
    op.add_column(
        "scan_findings",
        sa.Column("state_note", sa.Text(), nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column("state_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_findings_state", "scan_findings", ["state"])


def downgrade() -> None:
    op.drop_index("ix_scan_findings_state", table_name="scan_findings")
    op.drop_column("scan_findings", "state_updated_at")
    op.drop_column("scan_findings", "state_note")
    op.drop_column("scan_findings", "state")
