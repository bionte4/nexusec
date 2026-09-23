"""Recurring scan schedule models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.enums import ScanType, ScannerEngine, pg_enum

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.organization import Organization
    from app.models.scan import Scan
    from app.models.user import User


class ScanScheduleAsset(Base):
    """Many-to-many link between schedules and target assets."""

    __tablename__ = "scan_schedule_assets"

    schedule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_schedules.id", ondelete="CASCADE"),
        primary_key=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )


class ScanSchedule(Base):
    """Periodic scan definition evaluated by Celery Beat dispatcher."""

    __tablename__ = "scan_schedules"

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
    )
    engine: Mapped[ScannerEngine] = mapped_column(
        pg_enum(ScannerEngine, "scanner_engine"),
        nullable=False,
        index=True,
    )
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
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

    organization: Mapped[Organization] = relationship("Organization", back_populates="scan_schedules")
    created_by_user: Mapped[Optional[User]] = relationship("User")
    assets: Mapped[list[Asset]] = relationship(
        "Asset", secondary="scan_schedule_assets", back_populates="scan_schedules"
    )
    last_scan: Mapped[Optional[Scan]] = relationship("Scan", foreign_keys=[last_scan_id])

    def __repr__(self) -> str:
        return f"<ScanSchedule id={self.id} name={self.name!r} enabled={self.enabled}>"
