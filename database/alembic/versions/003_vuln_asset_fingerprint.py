"""switch vulnerability dedup to asset_id + fingerprint

Revision ID: 003_vuln_asset_fingerprint
Revises: 002_audit_status_code
Create Date: 2026-09-22

Note: Fresh installs already create uq_vulnerabilities_asset_fingerprint in 001.
This revision is a no-op when the new constraint already exists (idempotent-ish).
"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import inspect

revision: str = "003_vuln_asset_fingerprint"
down_revision: str | None = "002_audit_status_code"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    uniques = {
        u["name"] for u in inspector.get_unique_constraints("vulnerabilities")
    }
    if "uq_vulnerabilities_scan_fingerprint" in uniques:
        op.drop_constraint(
            "uq_vulnerabilities_scan_fingerprint",
            "vulnerabilities",
            type_="unique",
        )
    if "uq_vulnerabilities_asset_fingerprint" not in uniques:
        op.create_unique_constraint(
            "uq_vulnerabilities_asset_fingerprint",
            "vulnerabilities",
            ["asset_id", "fingerprint"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    uniques = {
        u["name"] for u in inspector.get_unique_constraints("vulnerabilities")
    }
    if "uq_vulnerabilities_asset_fingerprint" in uniques:
        op.drop_constraint(
            "uq_vulnerabilities_asset_fingerprint",
            "vulnerabilities",
            type_="unique",
        )
    if "uq_vulnerabilities_scan_fingerprint" not in uniques:
        op.create_unique_constraint(
            "uq_vulnerabilities_scan_fingerprint",
            "vulnerabilities",
            ["scan_id", "fingerprint"],
        )
