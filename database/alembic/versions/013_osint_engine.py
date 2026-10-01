"""Alembic migration: add osint to scanner_engine enum.

Revision ID: 013_osint_engine
Revises: 012_engagement_approvals
"""

from __future__ import annotations

from alembic import op

revision: str = "013_osint_engine"
down_revision: str = "012_engagement_approvals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE scanner_engine ADD VALUE IF NOT EXISTS 'osint'")


def downgrade() -> None:
    pass
