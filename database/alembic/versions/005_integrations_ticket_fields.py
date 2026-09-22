"""add external ticket fields for SIEM/SOAR ticketing sync

Revision ID: 005_integrations_ticket_fields
Revises: 004_remediation_tracker
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "005_integrations_ticket_fields"
down_revision: str | None = "004_remediation_tracker"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("external_ticket_system", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("external_ticket_key", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("external_ticket_url", sa.String(length=512), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("last_alerted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_vulnerabilities_external_ticket_key",
        "vulnerabilities",
        ["external_ticket_key"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_vulnerabilities_external_ticket_key", table_name="vulnerabilities"
    )
    op.drop_column("vulnerabilities", "last_alerted_at")
    op.drop_column("vulnerabilities", "external_ticket_url")
    op.drop_column("vulnerabilities", "external_ticket_key")
    op.drop_column("vulnerabilities", "external_ticket_system")
