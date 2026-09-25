"""Alembic migration: EPSS scores, remediation SLA due dates, retest link.

Revision ID: 009_epss_sla_retest
Revises: 008_scan_schedules
Create Date: 2026-09-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "009_epss_sla_retest"
down_revision: str | None = "008_scan_schedules"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "threat_intel_cves",
        sa.Column("epss_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "threat_intel_cves",
        sa.Column("epss_percentile", sa.Float(), nullable=True),
    )
    op.add_column(
        "threat_intel_cves",
        sa.Column("epss_fetched_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.add_column(
        "vulnerabilities",
        sa.Column("epss_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("epss_percentile", sa.Float(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("remediation_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "last_retest_scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_vulnerabilities_remediation_due_at",
        "vulnerabilities",
        ["remediation_due_at"],
    )
    op.create_index(
        "ix_vulnerabilities_epss_score",
        "vulnerabilities",
        ["epss_score"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_epss_score", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_remediation_due_at", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "last_retest_scan_id")
    op.drop_column("vulnerabilities", "remediation_due_at")
    op.drop_column("vulnerabilities", "epss_percentile")
    op.drop_column("vulnerabilities", "epss_score")
    op.drop_column("threat_intel_cves", "epss_fetched_at")
    op.drop_column("threat_intel_cves", "epss_percentile")
    op.drop_column("threat_intel_cves", "epss_score")
