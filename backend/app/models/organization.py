"""Multi-tenant Organization (tenant) model."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.audit_log import AuditLog
    from app.models.scan import Scan
    from app.models.scan_schedule import ScanSchedule
    from app.models.user import User
    from app.models.vulnerability import Vulnerability


class Organization(Base):
    """Tenant / client workspace boundary for multi-tenancy."""

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    # Workspace API token — store hash only; plaintext returned once on create/rotate
    workspace_token_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    workspace_token_prefix: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    users: Mapped[list[User]] = relationship("User", back_populates="organization")
    assets: Mapped[list[Asset]] = relationship("Asset", back_populates="organization")
    scans: Mapped[list[Scan]] = relationship("Scan", back_populates="organization")
    scan_schedules: Mapped[list[ScanSchedule]] = relationship(
        "ScanSchedule", back_populates="organization"
    )
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        "Vulnerability", back_populates="organization"
    )
    audit_logs: Mapped[list[AuditLog]] = relationship("AuditLog", back_populates="organization")

    def __repr__(self) -> str:
        return f"<Organization id={self.id} slug={self.slug!r}>"
