"""Email logs table for tracking sent emails.

Revision ID: 026
Revises: 025
Create Date: 2026-11-19
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "026"
down_revision = "024"  # 025 was deleted (org_name_unique reverted)
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "email_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("recipient", sa.String(255), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("template", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),  # sent, failed, pending
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),  # extra context (invite_id, user_id, etc)
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_email_logs_recipient", "email_logs", ["recipient"])
    op.create_index("ix_email_logs_created_at", "email_logs", ["created_at"])
    op.create_index("ix_email_logs_status", "email_logs", ["status"])


def downgrade() -> None:
    op.drop_table("email_logs")
