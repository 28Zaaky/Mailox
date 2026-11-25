"""Phase 4: asset registry + scope snapshots

Revision ID: 011
Revises: 010
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_type", sa.String(30), nullable=False),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("metadata", JSONB, nullable=False, server_default="{}"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("org_id", "asset_type", "value", name="uq_assets_org_type_value"),
    )
    op.create_index("ix_assets_org_id", "assets", ["org_id"])
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])

    op.create_table(
        "project_assets",
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("authorized", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("authorized_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("project_id", "asset_id"),
    )
    op.create_index("ix_project_assets_project_id", "project_assets", ["project_id"])

    op.create_table(
        "scope_snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("targets", JSONB, nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_scope_snapshots_scan_id", "scope_snapshots", ["scan_id"])


def downgrade() -> None:
    op.drop_table("scope_snapshots")
    op.drop_table("project_assets")
    op.drop_table("assets")
