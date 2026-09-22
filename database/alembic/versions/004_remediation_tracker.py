"""add remediation tracking fields, comments, finding_status values

Revision ID: 004_remediation_tracker
Revises: 003_vuln_asset_fingerprint
Create Date: 2026-09-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004_remediation_tracker"
down_revision: str | None = "003_vuln_asset_fingerprint"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add new enum values (PostgreSQL)
    op.execute("ALTER TYPE finding_status ADD VALUE IF NOT EXISTS 'in_progress'")
    op.execute("ALTER TYPE finding_status ADD VALUE IF NOT EXISTS 'resolved'")

    op.add_column(
        "vulnerabilities",
        sa.Column("remediation_owner_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("remediation_owner_label", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_vulnerabilities_remediation_owner_id_users",
        "vulnerabilities",
        "users",
        ["remediation_owner_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_vulnerabilities_remediation_owner_id",
        "vulnerabilities",
        ["remediation_owner_id"],
    )

    op.create_table(
        "vulnerability_comments",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vulnerability_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("author_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["author_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["vulnerabilities.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_vulnerability_comments_vulnerability_id",
        "vulnerability_comments",
        ["vulnerability_id"],
    )
    op.create_index(
        "ix_vulnerability_comments_author_id",
        "vulnerability_comments",
        ["author_id"],
    )
    op.create_index(
        "ix_vulnerability_comments_created_at",
        "vulnerability_comments",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_table("vulnerability_comments")
    op.drop_index(
        "ix_vulnerabilities_remediation_owner_id", table_name="vulnerabilities"
    )
    op.drop_constraint(
        "fk_vulnerabilities_remediation_owner_id_users",
        "vulnerabilities",
        type_="foreignkey",
    )
    op.drop_column("vulnerabilities", "status_changed_at")
    op.drop_column("vulnerabilities", "remediation_owner_label")
    op.drop_column("vulnerabilities", "remediation_owner_id")
    # Enum values cannot be removed safely in PostgreSQL — leave in place.
