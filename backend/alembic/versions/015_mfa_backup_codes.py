"""Add mfa_backup_codes_encrypted to users

Revision ID: 015
Revises: 014
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("mfa_backup_codes_encrypted", sa.String(2048), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "mfa_backup_codes_encrypted")
