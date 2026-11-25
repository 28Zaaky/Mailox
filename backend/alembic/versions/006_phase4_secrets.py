"""Phase 4: add exposed_secrets table (Module 07 — Credential Exposure Detection).

The table stores masked findings from file-based secret scans.
Plaintext secrets are NEVER persisted — only masked values.

Revision ID: 006
Revises: 005
Create Date: 2026-11-15
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "exposed_secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "source_type",
            sa.Enum(
                "config_file", "env_file", "git_history",
                "archive", "source_code", "log_file", "backup",
                name="secretsourcetype",
            ),
            nullable=False,
        ),
        sa.Column("source_name", sa.String(512), nullable=False),
        sa.Column("source_path", sa.String(1024), nullable=True),
        sa.Column(
            "secret_type",
            sa.Enum(
                "smtp_password", "smtp_username", "smtp_dsn", "smtp_host",
                "mail_api_key", "generic_password", "oauth_token",
                name="secrettype",
            ),
            nullable=False,
        ),
        sa.Column("masked_value", sa.String(512), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False, server_default="high"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("context_snippet", sa.Text(), nullable=True),
        sa.Column("detection_rule", sa.String(256), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "open", "confirmed", "false_positive", "remediated",
                name="exposedsecretstatus",
            ),
            nullable=False,
            server_default="open",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_exposed_secrets_org_id", "exposed_secrets", ["org_id"])
    op.create_index("ix_exposed_secrets_scan_id", "exposed_secrets", ["scan_id"])
    op.create_index(
        "ix_exposed_secrets_org_status",
        "exposed_secrets",
        ["org_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_exposed_secrets_org_status", "exposed_secrets")
    op.drop_index("ix_exposed_secrets_scan_id", "exposed_secrets")
    op.drop_index("ix_exposed_secrets_org_id", "exposed_secrets")
    op.drop_table("exposed_secrets")
    op.execute("DROP TYPE IF EXISTS exposedsecretstatus")
    op.execute("DROP TYPE IF EXISTS secrettype")
    op.execute("DROP TYPE IF EXISTS secretsourcetype")
