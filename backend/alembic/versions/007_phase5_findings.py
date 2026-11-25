"""Phase 5: extend scan_findings with lifecycle fields; add risk_score to scans.

Adds:
  scan_findings.status         — finding lifecycle (open/confirmed/etc.)
  scan_findings.affected_asset — target asset string
  scan_findings.references     — JSONB array of reference URLs
  scan_findings.last_seen_at   — timestamp of last detection
  scan_findings.cvss_score     — numeric CVSS score (NULL if not applicable)
  scans.risk_score             — 0-100 aggregate risk score from correlation engine

Revision ID: 007
Revises: 006
Create Date: 2026-11-16
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE TYPE findingstatus AS ENUM "
        "('open', 'confirmed', 'accepted_risk', 'in_remediation', 'resolved', 'false_positive')"
    )

    op.add_column(
        "scan_findings",
        sa.Column(
            "status",
            sa.Enum(
                "open", "confirmed", "accepted_risk",
                "in_remediation", "resolved", "false_positive",
                name="findingstatus",
            ),
            nullable=False,
            server_default="open",
        ),
    )
    op.add_column(
        "scan_findings",
        sa.Column("affected_asset", sa.String(255), nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column(
            "references",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )
    op.add_column(
        "scan_findings",
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column("cvss_score", sa.Float(), nullable=True),
    )

    op.create_index("ix_scan_findings_status", "scan_findings", ["status"])
    op.create_index(
        "ix_scan_findings_org_status",
        "scan_findings",
        ["status"],
    )

    # risk_score on scans — set by risk_correlation engine post-scan
    op.add_column(
        "scans",
        sa.Column("risk_score", sa.Float(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "risk_score")
    op.drop_index("ix_scan_findings_org_status", "scan_findings")
    op.drop_index("ix_scan_findings_status", "scan_findings")
    op.drop_column("scan_findings", "cvss_score")
    op.drop_column("scan_findings", "last_seen_at")
    op.drop_column("scan_findings", "references")
    op.drop_column("scan_findings", "affected_asset")
    op.drop_column("scan_findings", "status")
    op.execute("DROP TYPE IF EXISTS findingstatus")
