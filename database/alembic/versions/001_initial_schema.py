"""initial schema: users, assets, scans, vulnerabilities, audit_logs

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

user_role = postgresql.ENUM(
    "admin", "pentester", "soc_analyst", name="user_role", create_type=False
)
asset_type = postgresql.ENUM(
    "ip", "domain", "cloud_resource", name="asset_type", create_type=False
)
asset_criticality = postgresql.ENUM(
    "critical", "high", "medium", "low", name="asset_criticality", create_type=False
)
scan_type = postgresql.ENUM(
    "va", "pt", "discovery", "compliance", "custom", name="scan_type", create_type=False
)
scanner_engine = postgresql.ENUM(
    "nexusec",
    "nmap",
    "nuclei",
    "openvas",
    "other",
    name="scanner_engine",
    create_type=False,
)
scan_status = postgresql.ENUM(
    "pending",
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
    name="scan_status",
    create_type=False,
)
severity = postgresql.ENUM(
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unknown",
    name="severity",
    create_type=False,
)
finding_status = postgresql.ENUM(
    "open",
    "in_progress",
    "false_positive",
    "resolved",
    "confirmed",
    "accepted_risk",
    "remediated",
    "reopened",
    name="finding_status",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    user_role.create(bind, checkfirst=True)
    asset_type.create(bind, checkfirst=True)
    asset_criticality.create(bind, checkfirst=True)
    scan_type.create(bind, checkfirst=True)
    scanner_engine.create(bind, checkfirst=True)
    scan_status.create(bind, checkfirst=True)
    severity.create(bind, checkfirst=True)
    finding_status.create(bind, checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", user_role, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
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
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_role", "users", ["role"], unique=False)

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("asset_type", asset_type, nullable=False),
        sa.Column(
            "criticality",
            asset_criticality,
            nullable=False,
            server_default="medium",
        ),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("domain", sa.String(length=255), nullable=True),
        sa.Column("cloud_resource_id", sa.String(length=512), nullable=True),
        sa.Column("cloud_provider", sa.String(length=64), nullable=True),
        sa.Column(
            "is_cde_scope",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("url", sa.String(length=2048), nullable=True),
        sa.Column("environment", sa.String(length=64), nullable=True),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "tags",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), nullable=True),
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
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_assets_name", "assets", ["name"], unique=False)
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"], unique=False)
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"], unique=False)
    op.create_index("ix_assets_domain", "assets", ["domain"], unique=False)
    op.create_index(
        "ix_assets_cloud_resource_id", "assets", ["cloud_resource_id"], unique=False
    )
    op.create_index("ix_assets_is_cde_scope", "assets", ["is_cde_scope"], unique=False)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scan_type", scan_type, nullable=False),
        sa.Column(
            "engine",
            scanner_engine,
            nullable=False,
            server_default="nexusec",
        ),
        sa.Column(
            "status",
            scan_status,
            nullable=False,
            server_default="pending",
        ),
        sa.Column("progress", sa.Float(), nullable=False, server_default="0"),
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("celery_task_id", sa.String(length=255), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), nullable=True),
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
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_scan_type", "scans", ["scan_type"], unique=False)
    op.create_index("ix_scans_engine", "scans", ["engine"], unique=False)
    op.create_index("ix_scans_status", "scans", ["status"], unique=False)

    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"], unique=False)
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"], unique=False)
    op.create_index(
        "ix_audit_logs_resource_type", "audit_logs", ["resource_type"], unique=False
    )
    op.create_index(
        "ix_audit_logs_created_at", "audit_logs", ["created_at"], unique=False
    )

    op.create_table(
        "scan_assets",
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id", "asset_id"),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            severity,
            nullable=False,
            server_default="unknown",
        ),
        sa.Column(
            "status",
            finding_status,
            nullable=False,
            server_default="open",
        ),
        sa.Column("cve_id", sa.String(length=32), nullable=True),
        sa.Column("cwe_id", sa.String(length=32), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=128), nullable=True),
        sa.Column("affected_component", sa.String(length=512), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("owasp_category", sa.String(length=64), nullable=True),
        sa.Column(
            "mitre_attack_techniques",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "compliance_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "raw_source",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("source_tool", sa.String(length=64), nullable=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
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
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "asset_id", "fingerprint", name="uq_vulnerabilities_asset_fingerprint"
        ),
    )
    op.create_index(
        "ix_vulnerabilities_scan_id", "vulnerabilities", ["scan_id"], unique=False
    )
    op.create_index(
        "ix_vulnerabilities_asset_id", "vulnerabilities", ["asset_id"], unique=False
    )
    op.create_index(
        "ix_vulnerabilities_severity", "vulnerabilities", ["severity"], unique=False
    )
    op.create_index(
        "ix_vulnerabilities_status", "vulnerabilities", ["status"], unique=False
    )
    op.create_index(
        "ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"], unique=False
    )
    op.create_index("ix_vulnerabilities_cwe_id", "vulnerabilities", ["cwe_id"])
    op.create_index("ix_vulnerabilities_cvss_score", "vulnerabilities", ["cvss_score"])
    op.create_index(
        "ix_vulnerabilities_severity_status",
        "vulnerabilities",
        ["severity", "status"],
    )


def downgrade() -> None:
    op.drop_table("vulnerabilities")
    op.drop_table("scan_assets")
    op.drop_table("audit_logs")
    op.drop_table("scans")
    op.drop_table("assets")
    op.drop_table("users")

    bind = op.get_bind()
    finding_status.drop(bind, checkfirst=True)
    severity.drop(bind, checkfirst=True)
    scan_status.drop(bind, checkfirst=True)
    scanner_engine.drop(bind, checkfirst=True)
    scan_type.drop(bind, checkfirst=True)
    asset_criticality.drop(bind, checkfirst=True)
    asset_type.drop(bind, checkfirst=True)
    user_role.drop(bind, checkfirst=True)
