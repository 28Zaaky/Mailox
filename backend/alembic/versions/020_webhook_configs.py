"""Webhook configs — per-org HTTP callbacks on scan/finding events

Revision ID: 020
Revises: 019
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhook_configs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("events", postgresql.JSON(), nullable=False, server_default="[]"),
        sa.Column("secret", sa.String(256), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status_code", sa.Integer(), nullable=True),
    )
    op.create_index("ix_webhook_configs_org_id", "webhook_configs", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_webhook_configs_org_id", table_name="webhook_configs")
    op.drop_table("webhook_configs")
