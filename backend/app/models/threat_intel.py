"""Threat intelligence models — CISA KEV cache + sync run metadata."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Optional

from sqlalchemy import Boolean, Date, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ThreatIntelCve(Base):
    """Cached CVE threat-intel record (CISA KEV + optional NVD enrichment)."""

    __tablename__ = "threat_intel_cves"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    has_public_exploit: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )
    vendor_project: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    vulnerability_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    date_added: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    due_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    known_ransomware_use: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    required_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    nvd_cvss_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    nvd_exploitability_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    sources: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    raw_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class ThreatIntelSyncRun(Base):
    """Audit trail for periodic KEV/NVD sync jobs."""

    __tablename__ = "threat_intel_sync_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # kev | nvd | enrich
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="running"
    )  # running | success | failed
    records_upserted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    vulnerabilities_enriched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
