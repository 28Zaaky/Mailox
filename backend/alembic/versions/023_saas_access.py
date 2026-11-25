"""SaaS access control: access requests, single-use invites, verified domains

Revision ID: 023
Revises: 022
Create Date: 2026-11-18
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "access_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("company", sa.String(160), nullable=False),
        sa.Column("role", sa.String(120), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("topic", sa.String(20), nullable=False, server_default="access"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_access_requests_status_created", "access_requests", ["status", "created_at"])
    op.create_index("ix_access_requests_email", "access_requests", ["email"])

    op.create_table(
        "access_invites",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("request_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("access_requests.id", ondelete="SET NULL"), nullable=True),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_access_invites_email", "access_invites", ["email"])

    op.create_table(
        "verified_domains",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "domain", name="uq_verified_domains_org_domain"),
    )
    op.create_index("ix_verified_domains_org_id", "verified_domains", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_verified_domains_org_id", table_name="verified_domains")
    op.drop_table("verified_domains")
    op.drop_index("ix_access_invites_email", table_name="access_invites")
    op.drop_table("access_invites")
    op.drop_index("ix_access_requests_email", table_name="access_requests")
    op.drop_index("ix_access_requests_status_created", table_name="access_requests")
    op.drop_table("access_requests")
