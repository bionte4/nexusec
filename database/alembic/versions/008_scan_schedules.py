"""Alembic migration: recurring scan schedules.

Revision ID: 008_scan_schedules
Revises: 007_multi_tenancy
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "008_scan_schedules"
down_revision: str | None = "007_multi_tenancy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "scan_type",
            postgresql.ENUM(
                "va",
                "pt",
                "discovery",
                "compliance",
                "custom",
                name="scan_type",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "engine",
            postgresql.ENUM(
                "nexusec",
                "nmap",
                "nuclei",
                "openvas",
                "other",
                name="scanner_engine",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "last_scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_by_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
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
    op.create_index("ix_scan_schedules_organization_id", "scan_schedules", ["organization_id"])
    op.create_index("ix_scan_schedules_engine", "scan_schedules", ["engine"])
    op.create_index("ix_scan_schedules_enabled", "scan_schedules", ["enabled"])
    op.create_index("ix_scan_schedules_next_run_at", "scan_schedules", ["next_run_at"])

    op.create_table(
        "scan_schedule_assets",
        sa.Column(
            "schedule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_schedules.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )


def downgrade() -> None:
    op.drop_table("scan_schedule_assets")
    op.drop_index("ix_scan_schedules_next_run_at", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_enabled", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_engine", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_organization_id", table_name="scan_schedules")
    op.drop_table("scan_schedules")
