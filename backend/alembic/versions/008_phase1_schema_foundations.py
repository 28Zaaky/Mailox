"""Phase 1: Schema foundations — FK audit_logs, users.full_name, findings.fingerprint,
findings.status_changed_at / status_changed_by.

Changes:
  1. audit_logs.org_id — add FK to organizations(id) ON DELETE SET NULL
     (index already exists from migration 004)
  2. users.full_name VARCHAR(255) nullable
  3. scan_findings.fingerprint VARCHAR(64) nullable + index + backfill
  4. scan_findings.status_changed_at TIMESTAMP WITH TIME ZONE nullable
  5. scan_findings.status_changed_by UUID FK → users(id) ON DELETE SET NULL

Revision ID: 008
Revises: 007
Create Date: 2026-11-16
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # pgcrypto needed for digest() in fingerprint backfill
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # ── 1. FK audit_logs.org_id → organizations(id) ──────────────────────────
    # The index ix_audit_logs_org_id already exists (migration 004).
    # Only add the FK constraint if it doesn't exist yet.
    op.create_foreign_key(
        "audit_logs_org_id_fkey",
        "audit_logs",
        "organizations",
        ["org_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # ── 2. users.full_name ────────────────────────────────────────────────────
    op.add_column(
        "users",
        sa.Column("full_name", sa.String(255), nullable=True),
    )

    # ── 3. scan_findings.fingerprint ─────────────────────────────────────────
    op.add_column(
        "scan_findings",
        sa.Column("fingerprint", sa.String(64), nullable=True),
    )
    op.create_index("ix_scan_findings_fingerprint", "scan_findings", ["fingerprint"])

    # Backfill: SHA256(engine:check_id:affected_asset:org_id) via SQL
    # We JOIN scan_findings → scans to get org_id.
    op.execute("""
        UPDATE scan_findings sf
        SET fingerprint = encode(
            digest(
                sf.engine || ':' || sf.check_id || ':' ||
                COALESCE(sf.affected_asset, '') || ':' ||
                s.org_id::text,
                'sha256'
            ),
            'hex'
        )
        FROM scans s
        WHERE sf.scan_id = s.id
          AND sf.fingerprint IS NULL
    """)

    # ── 4. scan_findings.status_changed_at / status_changed_by ───────────────
    op.add_column(
        "scan_findings",
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column("status_changed_by", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "scan_findings_status_changed_by_fkey",
        "scan_findings",
        "users",
        ["status_changed_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_scan_findings_status_changed_by",
        "scan_findings",
        ["status_changed_by"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_findings_status_changed_by", "scan_findings")
    op.drop_constraint("scan_findings_status_changed_by_fkey", "scan_findings", type_="foreignkey")
    op.drop_column("scan_findings", "status_changed_by")
    op.drop_column("scan_findings", "status_changed_at")

    op.drop_index("ix_scan_findings_fingerprint", "scan_findings")
    op.drop_column("scan_findings", "fingerprint")

    op.drop_column("users", "full_name")

    op.drop_constraint("audit_logs_org_id_fkey", "audit_logs", type_="foreignkey")
