"""Phase 6: continuous monitoring schedules and deltas

Revision ID: 013
Revises: 012
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. monitoring_schedules
    op.execute("""
        CREATE TABLE monitoring_schedules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            profile_id UUID NOT NULL REFERENCES assessment_profiles(id),
            cron_expression VARCHAR(100) NOT NULL,
            enabled BOOL NOT NULL DEFAULT true,
            next_run_at TIMESTAMP WITH TIME ZONE,
            last_run_at TIMESTAMP WITH TIME ZONE,
            last_scan_id UUID REFERENCES scans(id),
            created_by UUID REFERENCES users(id),
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ix_monitoring_schedules_project_id ON monitoring_schedules(project_id)")
    op.execute("CREATE INDEX ix_monitoring_schedules_next_run_at ON monitoring_schedules(next_run_at) WHERE enabled = true")

    # 2. monitoring_deltas
    op.execute("""
        CREATE TABLE monitoring_deltas (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            schedule_id UUID NOT NULL REFERENCES monitoring_schedules(id) ON DELETE CASCADE,
            scan_id UUID NOT NULL REFERENCES scans(id),
            previous_scan_id UUID REFERENCES scans(id),
            new_findings INT NOT NULL DEFAULT 0,
            persistent_findings INT NOT NULL DEFAULT 0,
            resolved_findings INT NOT NULL DEFAULT 0,
            severity_changed INT NOT NULL DEFAULT 0,
            computed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ix_monitoring_deltas_schedule_id ON monitoring_deltas(schedule_id)")

    # 3. Add monitoring_schedule_id to scans (nullable — most scans are ad-hoc)
    op.execute("""
        ALTER TABLE scans
            ADD COLUMN monitoring_schedule_id UUID REFERENCES monitoring_schedules(id) ON DELETE SET NULL
    """)
    op.execute("CREATE INDEX ix_scans_monitoring_schedule_id ON scans(monitoring_schedule_id)")


def downgrade() -> None:
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS monitoring_schedule_id")
    op.execute("DROP TABLE IF EXISTS monitoring_deltas")
    op.execute("DROP TABLE IF EXISTS monitoring_schedules")
