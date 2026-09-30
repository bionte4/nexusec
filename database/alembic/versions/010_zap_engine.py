"""Alembic migration: add zap to scanner_engine enum.

Revision ID: 010_zap_engine
Revises: 009_epss_sla_retest
"""

from __future__ import annotations

from alembic import op

revision: str = "010_zap_engine"
down_revision: str = "009_epss_sla_retest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PostgreSQL ENUM: ADD VALUE cannot run inside a transaction block on older PG;
    # Alembic usually autocommits this via EXECUTE.
    op.execute("ALTER TYPE scanner_engine ADD VALUE IF NOT EXISTS 'zap'")


def downgrade() -> None:
    # Removing enum values is not supported cleanly on PostgreSQL; leave as no-op.
    pass
