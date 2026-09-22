"""Pydantic schemas for Users, Assets, Scans, and Vulnerabilities."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.core.enums import (
    FindingStatus,
    Severity,
    UserRole,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Users ---


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=128)
    role: UserRole = UserRole.SOC_ANALYST


class UserRead(ORMModel):
    id: uuid.UUID
    email: EmailStr
    full_name: str
    role: UserRole
    organization_id: uuid.UUID | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class UserListResponse(BaseModel):
    items: list[UserRead]
    total: int
    page: int
    page_size: int
    pages: int


# --- Assets (see app.schemas.asset) ---

from app.schemas.asset import (  # noqa: E402
    AssetCreate,
    AssetListResponse,
    AssetRead,
    AssetUpdate,
)

# --- Scans (see app.schemas.scan) ---

from app.schemas.scan import (  # noqa: E402
    ScanCreate,
    ScanEnqueueResponse,
    ScanListResponse,
    ScanRead,
)

# --- Vulnerabilities (normalized finding) ---


class ComplianceTags(BaseModel):
    """Structured compliance mapping attached to every finding."""

    iso27001: list[str] = Field(
        default_factory=list,
        description="ISO 27001 Annex A controls, e.g. A.8.8",
        validation_alias="iso_27001",
        serialization_alias="iso_27001",
    )
    pci_dss: list[str] = Field(
        default_factory=list,
        description="PCI-DSS requirements, e.g. 11.3.1",
    )
    gdpr: list[str] = Field(
        default_factory=list,
        description="GDPR articles / risk labels, e.g. Art.32",
    )
    nist_csf: list[str] = Field(
        default_factory=list,
        description="NIST CSF categories, e.g. ID.RA-1",
    )
    notes: str | None = None


class VulnerabilityCreate(BaseModel):
    scan_id: uuid.UUID
    asset_id: uuid.UUID
    fingerprint: str = Field(min_length=8, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    description: str | None = None
    severity: Severity = Severity.UNKNOWN
    status: FindingStatus = FindingStatus.OPEN
    affected_component: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    owasp_category: str | None = None
    mitre_attack_techniques: list[str] = Field(default_factory=list)
    compliance_metadata: ComplianceTags = Field(default_factory=ComplianceTags)
    raw_source: dict[str, Any] = Field(default_factory=dict)
    source_tool: str | None = None


class VulnerabilityRead(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    asset_id: uuid.UUID
    fingerprint: str
    title: str
    description: str | None
    severity: Severity
    status: FindingStatus
    affected_component: str | None
    port: int | None
    protocol: str | None
    evidence: dict[str, Any]
    remediation: str | None
    cve_id: str | None
    cwe_id: str | None
    cvss_score: float | None
    cvss_vector: str | None
    owasp_category: str | None
    mitre_attack_techniques: list[Any]
    compliance_metadata: dict[str, Any]
    source_tool: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
