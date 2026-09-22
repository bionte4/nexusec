"""Scan job and scan↔asset association models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.enums import ScanStatus, ScanType, ScannerEngine, pg_enum

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.organization import Organization
    from app.models.user import User
    from app.models.vulnerability import Vulnerability


class ScanAsset(Base):
    """Many-to-many link between scans and target assets."""

    __tablename__ = "scan_assets"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        primary_key=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(
        pg_enum(ScanType, "scan_type"),
        nullable=False,
        index=True,
    )
    engine: Mapped[ScannerEngine] = mapped_column(
        pg_enum(ScannerEngine, "scanner_engine"),
        default=ScannerEngine.NEXUSEC,
        nullable=False,
        index=True,
    )
    status: Mapped[ScanStatus] = mapped_column(
        pg_enum(ScanStatus, "scan_status"),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )
    progress: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    created_by_user: Mapped[Optional[User]] = relationship("User", back_populates="scans")
    organization: Mapped[Organization] = relationship("Organization", back_populates="scans")
    assets: Mapped[list[Asset]] = relationship(
        "Asset", secondary="scan_assets", back_populates="scans"
    )
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        "Vulnerability", back_populates="scan"
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} name={self.name!r} status={self.status}>"
