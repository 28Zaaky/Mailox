"""Per-org settings — API keys and scan preferences overriding .env globals

Revision ID: 021
Revises: 020
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_settings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Encrypted API keys
        sa.Column("github_token_enc", sa.Text(), nullable=True),
        sa.Column("intelx_api_key_enc", sa.Text(), nullable=True),
        sa.Column("nvd_api_key_enc", sa.Text(), nullable=True),
        # Scan preferences
        sa.Column("canary_email", sa.String(254), nullable=True),
        sa.Column("cred_probe_enabled", sa.Boolean(), nullable=True),
        sa.Column("scan_timeout_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_org_settings_org_id_unique",
        "org_settings",
        ["org_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_org_settings_org_id_unique", table_name="org_settings")
    op.drop_table("org_settings")
