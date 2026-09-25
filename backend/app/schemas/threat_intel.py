"""Threat intelligence API schemas."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import FindingStatus, Severity


class ThreatIntelSyncRunRead(BaseModel):
    id: str
    source: str
    status: str
    records_upserted: int
    vulnerabilities_enriched: int
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error_message: Optional[str] = None


class ThreatIntelStatusResponse(BaseModel):
    kev_catalog_entries: int
    cves_with_public_exploit: int
    actively_exploited_open_findings: int
    last_sync_runs: list[ThreatIntelSyncRunRead] = Field(default_factory=list)
    kev_catalog_url: str
    sync_enabled: bool


class ActivelyExploitedItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    cve_id: Optional[str]
    severity: Severity
    status: FindingStatus
    asset_id: uuid.UUID
    cvss_score: Optional[float]
    is_actively_exploited: bool
    has_public_exploit: bool
    threat_risk_score: Optional[float]
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev_date_added: Optional[date]
    kev_due_date: Optional[date]
    threat_intel_metadata: dict[str, Any] = Field(default_factory=dict)
    threat_enriched_at: Optional[datetime] = None


class ActivelyExploitedListResponse(BaseModel):
    items: list[ActivelyExploitedItem]
    total: int
    page: int
    page_size: int
    pages: int


class ThreatIntelSyncRequest(BaseModel):
    sync_kev: bool = True
    enrich: bool = True
    fetch_nvd: bool = False  # default off for manual sync speed; beat job may enable
    enrich_limit: int = Field(default=500, ge=1, le=5000)


class ThreatIntelSyncResponse(BaseModel):
    kev: Optional[dict[str, Any]] = None
    enrich: Optional[dict[str, Any]] = None
    task_ids: list[str] = Field(default_factory=list)
