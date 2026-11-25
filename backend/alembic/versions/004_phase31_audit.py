"""Phase 3.1: Reliability audit — lease, engine runs, partial status

Revision ID: 004
Revises: 003
Create Date: 2026-11-13
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PARTIAL scan status
    op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'partial' AFTER 'completed'")

    # Lease + heartbeat columns on scans
    op.add_column("scans", sa.Column("attempt_number", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("worker_lease_id", sa.String(36), nullable=True))
    op.add_column("scans", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))

    # Drop non-unique idempotency index, replace with unique partial index
    op.drop_index("ix_scans_idempotency", table_name="scans")
    op.execute(
        "CREATE UNIQUE INDEX ix_scans_idempotency_unique "
        "ON scans (org_id, idempotency_key) "
        "WHERE idempotency_key IS NOT NULL"
    )

    # scan_engine_runs table
    op.create_table(
        "scan_engine_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("engine", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_msg", sa.Text(), nullable=True),
    )
    op.create_index("ix_engine_runs_scan_id", "scan_engine_runs", ["scan_id"])
    op.create_unique_constraint(
        "uq_engine_runs_scan_attempt_engine",
        "scan_engine_runs",
        ["scan_id", "attempt_number", "engine"],
    )

    # Outbox: add attempt_count and locked_until for safe concurrent recovery
    op.add_column(
        "scan_outbox",
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scan_outbox",
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_outbox", "locked_until")
    op.drop_column("scan_outbox", "attempt_count")

    op.drop_constraint("uq_engine_runs_scan_attempt_engine", "scan_engine_runs", type_="unique")
    op.drop_index("ix_engine_runs_scan_id", table_name="scan_engine_runs")
    op.drop_table("scan_engine_runs")

    op.execute("DROP INDEX IF EXISTS ix_scans_idempotency_unique")
    op.create_index("ix_scans_idempotency", "scans", ["org_id", "idempotency_key"])

    op.drop_column("scans", "heartbeat_at")
    op.drop_column("scans", "lease_expires_at")
    op.drop_column("scans", "worker_lease_id")
    op.drop_column("scans", "attempt_number")
    # PostgreSQL does not support removing enum values
