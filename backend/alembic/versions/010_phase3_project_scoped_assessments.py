"""Phase 3: project-scoped assessments + canonical finding deduplication

Revision ID: 010
Revises: 009
Create Date: 2026-11-16
"""
from alembic import op

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add project_id to scans
    op.execute("""
        ALTER TABLE scans
            ADD COLUMN project_id UUID REFERENCES projects(id) ON DELETE SET NULL
    """)
    op.execute("CREATE INDEX ix_scans_project_id ON scans(project_id)")

    # 2. Canonical findings table
    op.execute("""
        CREATE TABLE findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
            fingerprint VARCHAR(64) NOT NULL,
            engine VARCHAR(60) NOT NULL,
            check_id VARCHAR(120) NOT NULL,
            title VARCHAR(500) NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'open',
            risk_level VARCHAR(20) NOT NULL,
            assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
            first_detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
            last_detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
            observation_count INT NOT NULL DEFAULT 1,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            UNIQUE(fingerprint, project_id)
        )
    """)
    op.execute("CREATE INDEX ix_findings_project ON findings(project_id)")
    op.execute("CREATE INDEX ix_findings_fingerprint ON findings(fingerprint)")
    op.execute("CREATE INDEX ix_findings_org_id ON findings(org_id)")

    # 3. Finding status history table
    op.execute("""
        CREATE TABLE finding_status_history (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_finding_id UUID REFERENCES scan_findings(id) ON DELETE CASCADE,
            canonical_finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
            actor UUID REFERENCES users(id) ON DELETE SET NULL,
            prev_status VARCHAR(30),
            new_status VARCHAR(30) NOT NULL,
            reason VARCHAR(500),
            comment TEXT,
            changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)
    op.execute(
        "CREATE INDEX ix_finding_status_history_canonical "
        "ON finding_status_history(canonical_finding_id)"
    )
    op.execute(
        "CREATE INDEX ix_finding_status_history_scan_finding "
        "ON finding_status_history(scan_finding_id)"
    )

    # 4. Add canonical_finding_id to scan_findings
    op.execute("""
        ALTER TABLE scan_findings
            ADD COLUMN canonical_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL
    """)
    op.execute(
        "CREATE INDEX ix_scan_findings_canonical_finding_id "
        "ON scan_findings(canonical_finding_id)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scan_findings_canonical_finding_id")
    op.execute(
        "ALTER TABLE scan_findings DROP COLUMN IF EXISTS canonical_finding_id"
    )

    op.execute("DROP INDEX IF EXISTS ix_finding_status_history_scan_finding")
    op.execute("DROP INDEX IF EXISTS ix_finding_status_history_canonical")
    op.execute("DROP TABLE IF EXISTS finding_status_history")

    op.execute("DROP INDEX IF EXISTS ix_findings_org_id")
    op.execute("DROP INDEX IF EXISTS ix_findings_fingerprint")
    op.execute("DROP INDEX IF EXISTS ix_findings_project")
    op.execute("DROP TABLE IF EXISTS findings")

    op.execute("DROP INDEX IF EXISTS ix_scans_project_id")
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS project_id")
