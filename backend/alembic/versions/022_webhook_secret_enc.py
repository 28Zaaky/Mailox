"""Encrypt webhook secrets at rest: rename secret → secret_enc, widen column

Revision ID: 022
Revises: 021
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Rename column and widen to hold Fernet ciphertext (~1024 chars)
    op.alter_column(
        "webhook_configs",
        "secret",
        new_column_name="secret_enc",
        existing_type=sa.String(256),
        type_=sa.String(1024),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "webhook_configs",
        "secret_enc",
        new_column_name="secret",
        existing_type=sa.String(1024),
        type_=sa.String(256),
        existing_nullable=True,
    )
