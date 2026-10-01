"""Alembic migration: engagement_approvals for dual-control client delivery.

Revision ID: 012_engagement_approvals
Revises: 011_platform_settings
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "012_engagement_approvals"
down_revision: str = "011_platform_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "engagement_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("engagement_type", sa.String(length=32), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "approved_by_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "approved_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "revoked_by_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_engagement_approvals_organization_id",
        "engagement_approvals",
        ["organization_id"],
    )
    op.create_index(
        "ix_engagement_approvals_scan_id", "engagement_approvals", ["scan_id"]
    )
    op.create_index(
        "ix_engagement_approvals_asset_id", "engagement_approvals", ["asset_id"]
    )
    op.create_index(
        "ix_engagement_approvals_approved_by_id",
        "engagement_approvals",
        ["approved_by_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_engagement_approvals_approved_by_id", table_name="engagement_approvals")
    op.drop_index("ix_engagement_approvals_asset_id", table_name="engagement_approvals")
    op.drop_index("ix_engagement_approvals_scan_id", table_name="engagement_approvals")
    op.drop_index(
        "ix_engagement_approvals_organization_id", table_name="engagement_approvals"
    )
    op.drop_table("engagement_approvals")
