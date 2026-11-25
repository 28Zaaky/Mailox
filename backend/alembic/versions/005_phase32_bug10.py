"""Phase 3.2: Fix BUG-10 — created_by nullable=False incompatible with ondelete=SET NULL

Strategy: make created_by nullable=True so PostgreSQL can SET NULL when a user is
deleted. Scan history is fully preserved; created_by becomes NULL instead of
blocking user deletion.

Revision ID: 005
Revises: 004
Create Date: 2026-11-13
"""
from typing import Sequence, Union

from alembic import op

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Allow NULL so PostgreSQL can honour ondelete=SET NULL when a user is deleted.
    op.alter_column("scans", "created_by", nullable=True)


def downgrade() -> None:
    # Restore NOT NULL constraint — will fail if any row has NULL created_by.
    # Callers must backfill before downgrading.
    op.alter_column("scans", "created_by", nullable=False)
