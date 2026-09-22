"""add organizations and multi-tenant organization_id columns

Revision ID: 007_multi_tenancy
Revises: 006_threat_intel
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "007_multi_tenancy"
down_revision: str | None = "006_threat_intel"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT_ORG_ID = "00000000-0000-4000-8000-000000000001"


def upgrade() -> None:
    # Extend user_role enum with super_admin (PostgreSQL)
    op.execute("ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'super_admin'")

    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("workspace_token_hash", sa.String(length=255), nullable=True),
        sa.Column("workspace_token_prefix", sa.String(length=16), nullable=True),
        sa.Column(
            "settings",
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
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)
    op.create_index("ix_organizations_is_active", "organizations", ["is_active"])

    # Seed default tenant for existing rows
    op.execute(
        sa.text(
            """
            INSERT INTO organizations (id, name, slug, description, is_active, settings)
            VALUES (
                :id,
                'Default Organization',
                'default',
                'Bootstrap tenant for pre-multi-tenancy data',
                true,
                '{}'::jsonb
            )
            ON CONFLICT DO NOTHING
            """
        ).bindparams(id=DEFAULT_ORG_ID)
    )

    op.add_column(
        "users",
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_users_organization_id", "users", ["organization_id"])
    op.execute(
        sa.text("UPDATE users SET organization_id = :oid WHERE organization_id IS NULL").bindparams(
            oid=DEFAULT_ORG_ID
        )
    )
    op.create_foreign_key(
        "fk_users_organization_id",
        "users",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    for table in ("assets", "scans", "vulnerabilities"):
        op.add_column(
            table,
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
        op.execute(
            sa.text(
                f"UPDATE {table} SET organization_id = :oid WHERE organization_id IS NULL"
            ).bindparams(oid=DEFAULT_ORG_ID)
        )
        op.alter_column(table, "organization_id", nullable=False)
        op.create_index(f"ix_{table}_organization_id", table, ["organization_id"])
        op.create_foreign_key(
            f"fk_{table}_organization_id",
            table,
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )

    op.add_column(
        "audit_logs",
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_audit_logs_organization_id", "audit_logs", ["organization_id"])
    op.execute(
        sa.text(
            "UPDATE audit_logs SET organization_id = :oid WHERE organization_id IS NULL"
        ).bindparams(oid=DEFAULT_ORG_ID)
    )
    op.create_foreign_key(
        "fk_audit_logs_organization_id",
        "audit_logs",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_audit_logs_organization_id", "audit_logs", type_="foreignkey")
    op.drop_index("ix_audit_logs_organization_id", table_name="audit_logs")
    op.drop_column("audit_logs", "organization_id")

    for table in ("vulnerabilities", "scans", "assets"):
        op.drop_constraint(f"fk_{table}_organization_id", table, type_="foreignkey")
        op.drop_index(f"ix_{table}_organization_id", table_name=table)
        op.drop_column(table, "organization_id")

    op.drop_constraint("fk_users_organization_id", "users", type_="foreignkey")
    op.drop_index("ix_users_organization_id", table_name="users")
    op.drop_column("users", "organization_id")

    op.drop_index("ix_organizations_is_active", table_name="organizations")
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_table("organizations")
    # Note: PostgreSQL cannot easily remove enum values; leave super_admin in place.
