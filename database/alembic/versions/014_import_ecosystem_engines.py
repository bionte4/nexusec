"""Alembic migration: add import-ecosystem scanner_engine values.

Revision ID: 014_import_ecosystem_engines
Revises: 013_osint_engine
"""

from __future__ import annotations

from alembic import op

revision: str = "014_import_ecosystem_engines"
down_revision: str = "013_osint_engine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for value in ("sarif", "generic", "trivy", "burp", "nessus"):
        op.execute(f"ALTER TYPE scanner_engine ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    pass
