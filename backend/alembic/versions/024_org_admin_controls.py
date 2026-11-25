"""Per-organization limits a platform admin can set: daily scan quota, offensive modules

Revision ID: 024
Revises: 023
Create Date: 2026-11-18
"""
from alembic import op
import sqlalchemy as sa

revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # NULL = use the service default
    op.add_column("organizations", sa.Column("daily_scan_quota", sa.Integer(), nullable=True))
    op.add_column(
        "organizations",
        sa.Column("offensive_modules_allowed", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    op.drop_column("organizations", "offensive_modules_allowed")
    op.drop_column("organizations", "daily_scan_quota")
