"""Asset inventory — IP, Domain, Cloud Resource, with PCI-DSS CDE scope."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.enums import AssetCriticality, AssetType

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.scan import Scan
    from app.models.vulnerability import Vulnerability


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[AssetType] = mapped_column(
        Enum(AssetType, name="asset_type", native_enum=True),
        nullable=False,
        index=True,
    )
    criticality: Mapped[AssetCriticality] = mapped_column(
        Enum(AssetCriticality, name="asset_criticality", native_enum=True),
        default=AssetCriticality.MEDIUM,
        nullable=False,
    )

    # Type-specific identifiers
    ip_address: Mapped[Optional[str]] = mapped_column(INET, nullable=True, index=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    cloud_resource_id: Mapped[Optional[str]] = mapped_column(String(512), nullable=True, index=True)
    cloud_provider: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # PCI-DSS Cardholder Data Environment scope flag
    is_cde_scope: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    environment: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )
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

    organization: Mapped[Organization] = relationship("Organization", back_populates="assets")
    scans: Mapped[list[Scan]] = relationship(
        "Scan", secondary="scan_assets", back_populates="assets"
    )
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        "Vulnerability", back_populates="asset"
    )

    def __repr__(self) -> str:
        return f"<Asset id={self.id} name={self.name!r} type={self.asset_type}>"
