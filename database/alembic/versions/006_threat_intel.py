"""add threat intelligence tables and vulnerability RBVM fields

Revision ID: 006_threat_intel
Revises: 005_integrations_ticket_fields
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "006_threat_intel"
down_revision: str | None = "005_integrations_ticket_fields"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threat_intel_cves",
        sa.Column("cve_id", sa.String(length=32), primary_key=True),
        sa.Column("in_kev", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "has_public_exploit", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("vendor_project", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("vulnerability_name", sa.String(length=512), nullable=True),
        sa.Column("date_added", sa.Date(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("known_ransomware_use", sa.String(length=32), nullable=True),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("nvd_cvss_score", sa.Float(), nullable=True),
        sa.Column("nvd_exploitability_score", sa.Float(), nullable=True),
        sa.Column(
            "sources",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "raw_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
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
    op.create_index("ix_threat_intel_cves_in_kev", "threat_intel_cves", ["in_kev"])
    op.create_index(
        "ix_threat_intel_cves_has_public_exploit",
        "threat_intel_cves",
        ["has_public_exploit"],
    )

    op.create_table(
        "threat_intel_sync_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="running"),
        sa.Column("records_upserted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("vulnerabilities_enriched", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_threat_intel_sync_runs_source", "threat_intel_sync_runs", ["source"])

    op.add_column(
        "vulnerabilities",
        sa.Column(
            "is_actively_exploited",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "has_public_exploit",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column("vulnerabilities", sa.Column("kev_date_added", sa.Date(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("kev_due_date", sa.Date(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("threat_risk_score", sa.Float(), nullable=True))
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "threat_intel_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("threat_enriched_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_vulnerabilities_is_actively_exploited",
        "vulnerabilities",
        ["is_actively_exploited"],
    )
    op.create_index(
        "ix_vulnerabilities_threat_risk_score",
        "vulnerabilities",
        ["threat_risk_score"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_threat_risk_score", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_is_actively_exploited", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "threat_enriched_at")
    op.drop_column("vulnerabilities", "threat_intel_metadata")
    op.drop_column("vulnerabilities", "threat_risk_score")
    op.drop_column("vulnerabilities", "kev_due_date")
    op.drop_column("vulnerabilities", "kev_date_added")
    op.drop_column("vulnerabilities", "has_public_exploit")
    op.drop_column("vulnerabilities", "is_actively_exploited")

    op.drop_index("ix_threat_intel_sync_runs_source", table_name="threat_intel_sync_runs")
    op.drop_table("threat_intel_sync_runs")
    op.drop_index("ix_threat_intel_cves_has_public_exploit", table_name="threat_intel_cves")
    op.drop_index("ix_threat_intel_cves_in_kev", table_name="threat_intel_cves")
    op.drop_table("threat_intel_cves")
