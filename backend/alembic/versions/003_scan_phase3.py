"""Phase 3: add queued status, progress fields, outbox table

Revision ID: 003
Revises: 002
Create Date: 2026-11-13
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Add 'queued' to scan_status enum ─────────────────────────────────────
    op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'queued' BEFORE 'running'")

    # ── New columns on scans ──────────────────────────────────────────────────
    op.add_column("scans", sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("scans", sa.Column("current_engine", sa.String(50), nullable=True))
    op.add_column("scans", sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("idempotency_key", sa.String(255), nullable=True))
    op.add_column("scans", sa.Column("celery_task_id", sa.String(255), nullable=True))

    op.create_index("ix_scans_idempotency", "scans", ["org_id", "idempotency_key"])

    # ── scan_outbox table ─────────────────────────────────────────────────────
    op.create_table(
        "scan_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("published", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_outbox_published", "scan_outbox", ["published"])


def downgrade() -> None:
    op.drop_index("ix_scan_outbox_published", table_name="scan_outbox")
    op.drop_table("scan_outbox")

    op.drop_index("ix_scans_idempotency", table_name="scans")
    op.drop_column("scans", "celery_task_id")
    op.drop_column("scans", "idempotency_key")
    op.drop_column("scans", "progress_pct")
    op.drop_column("scans", "current_engine")
    op.drop_column("scans", "cancel_requested")

    # PostgreSQL doesn't support removing enum values — manual step if needed
