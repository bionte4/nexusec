"""add status_code to audit_logs

Revision ID: 002_audit_status_code
Revises: 001_initial_schema
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "002_audit_status_code"
down_revision: str | None = "001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_logs",
        sa.Column("status_code", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("audit_logs", "status_code")
