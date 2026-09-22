"""Compliance report response schemas (JSON / PDF-ready)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.core.enums import FindingStatus, Severity


class ReportMetadata(BaseModel):
    report_id: uuid.UUID
    report_type: str
    title: str
    standard: str
    generated_at: datetime
    auditor_user_id: uuid.UUID
    auditor_name: str
    auditor_email: str
    auditor_role: str
    scope_total_assets: int
    scope_cde_assets: int = 0
    scope_active_findings: int
    scope_notes: Optional[str] = None
    export_format: str = "json_pdf_ready"


class ReportFindingRow(BaseModel):
    vulnerability_id: uuid.UUID
    title: str
    severity: Severity
    status: FindingStatus
    asset_id: uuid.UUID
    asset_name: str
    is_cde_scope: bool = False
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    controls: list[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime


class ControlBucket(BaseModel):
    control_id: str
    control_title: str
    finding_count: int
    severity_summary: dict[str, int]
    findings: list[ReportFindingRow]


class ReportSection(BaseModel):
    """PDF-ready section block."""

    heading: str
    summary: str
    metrics: dict[str, Any] = Field(default_factory=dict)
    tables: list[dict[str, Any]] = Field(default_factory=list)
    narrative: Optional[str] = None


class ComplianceReport(BaseModel):
    metadata: ReportMetadata
    executive_summary: str
    sections: list[ReportSection]
    control_mapping: list[ControlBucket]
    findings: list[ReportFindingRow]
    recommendations: list[str] = Field(default_factory=list)
