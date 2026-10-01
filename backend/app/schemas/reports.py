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
    scope_asset_id: Optional[uuid.UUID] = None
    scope_asset_name: Optional[str] = None
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


class EngagementScanInfo(BaseModel):
    scan_id: uuid.UUID
    name: str
    scan_type: str
    engine: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    asset_names: list[str] = Field(default_factory=list)
    roe_notes: Optional[str] = None
    roe_id: Optional[str] = None
    tool_version: Optional[str] = None
    template_hash: Optional[str] = None


class EngagementFindingRow(BaseModel):
    vulnerability_id: uuid.UUID
    title: str
    severity: Severity
    status: FindingStatus
    asset_id: uuid.UUID
    asset_name: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    source_tool: Optional[str] = None
    port: Optional[int] = None
    remediation_excerpt: Optional[str] = None
    remediation_owner_label: Optional[str] = None
    last_retest_scan_id: Optional[uuid.UUID] = None
    verification_state: str = "unverified"
    # unverified | retested | closed_with_retest | closed_without_retest | false_positive
    evidence_excerpt: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime


class VerificationRow(BaseModel):
    vulnerability_id: uuid.UUID
    title: str
    severity: Severity
    status: FindingStatus
    asset_name: str
    before: str
    after: str
    retest_scan_id: Optional[uuid.UUID] = None
    gap: Optional[str] = None


class EngagementReport(BaseModel):
    """VA/PT engagement report (client-facing, PDF-ready)."""

    metadata: ReportMetadata
    engagement_type: str  # va | pt | mixed | custom
    classification: str = "Confidential — Client Deliverable"
    delivery: str = "draft"  # draft | client
    dual_control: dict[str, Any] = Field(default_factory=dict)
    executive_summary: str
    scope: ReportSection
    methodology: ReportSection
    limitations: ReportSection
    playbook: ReportSection
    ptes_checklist: ReportSection
    asvs_checklist: ReportSection
    severity_summary: dict[str, int] = Field(default_factory=dict)
    status_summary: dict[str, int] = Field(default_factory=dict)
    scans: list[EngagementScanInfo] = Field(default_factory=list)
    top_findings: list[EngagementFindingRow] = Field(default_factory=list)
    findings: list[EngagementFindingRow] = Field(default_factory=list)
    remediation_highlights: list[str] = Field(default_factory=list)
    verification_matrix: list[VerificationRow] = Field(default_factory=list)
    retest_summary: ReportSection
    recommendations: list[str] = Field(default_factory=list)
    disclaimer: str = (
        "This report is generated from NexuSec orchestration data. "
        "Human review is required before client delivery. "
        "Only authorized targets under a written Rules of Engagement (RoE) may be assessed."
    )
    export_warnings: list[str] = Field(default_factory=list)
    mock_policy: dict[str, Any] = Field(default_factory=dict)
