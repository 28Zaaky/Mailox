"""Phase 5: assessment profiles + profile_id on scans

Revision ID: 012
Revises: 011
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. assessment_profiles table (org_id nullable to allow global builtins)
    op.execute("""
        CREATE TABLE assessment_profiles (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            engines JSONB NOT NULL DEFAULT '["dns_auth","smtp_discovery","webmail","vuln_intel"]',
            config JSONB DEFAULT '{}',
            time_limit_seconds INT NOT NULL DEFAULT 3600,
            created_by UUID REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            is_builtin BOOL NOT NULL DEFAULT false
        )
    """)
    op.execute("CREATE INDEX ix_assessment_profiles_org_id ON assessment_profiles(org_id)")
    op.execute("CREATE INDEX ix_assessment_profiles_project_id ON assessment_profiles(project_id)")

    # 2. Seed 3 global built-in profiles (org_id=NULL = global)
    op.execute("""
        INSERT INTO assessment_profiles (id, org_id, name, engines, time_limit_seconds, is_builtin)
        VALUES
          ('a0000000-0000-0000-0000-000000000001', NULL,
           'Quick', '["dns_auth"]', 600, true),
          ('a0000000-0000-0000-0000-000000000002', NULL,
           'Standard', '["dns_auth","smtp_discovery"]', 1800, true),
          ('a0000000-0000-0000-0000-000000000003', NULL,
           'Full', '["dns_auth","smtp_discovery","webmail","vuln_intel"]', 3600, true)
    """)

    # 3. Add profile_id to scans
    op.execute("""
        ALTER TABLE scans
            ADD COLUMN profile_id UUID REFERENCES assessment_profiles(id) ON DELETE SET NULL
    """)
    op.execute("CREATE INDEX ix_scans_profile_id ON scans(profile_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scans_profile_id")
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS profile_id")

    op.execute("DROP INDEX IF EXISTS ix_assessment_profiles_project_id")
    op.execute("DROP INDEX IF EXISTS ix_assessment_profiles_org_id")
    op.execute("DROP TABLE IF EXISTS assessment_profiles")
