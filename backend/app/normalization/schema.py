"""Unified normalized vulnerability finding schema (Prompt 4)."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from app.core.enums import Severity


class NormalizedFinding(BaseModel):
    """
    Single canonical finding shape for all scanners.

    Maps 1:1 into DB columns + compliance_metadata JSON.
    """

    vuln_id: str = Field(
        min_length=1,
        max_length=128,
        description="Stable finding identifier used as fingerprint seed",
    )
    name: str = Field(min_length=1, max_length=512)
    description: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cwe_id: Optional[str] = Field(default=None, max_length=32)

    mitre_tactics: list[str] = Field(default_factory=list)
    remediation_steps: Optional[str] = None

    iso_27001_clause: list[str] = Field(default_factory=list)
    pci_dss_requirement: list[str] = Field(default_factory=list)
    gdpr_risk_flag: bool = False

    # Location / taxonomy extras
    cve_id: Optional[str] = Field(default=None, max_length=32)
    cvss_vector: Optional[str] = Field(default=None, max_length=128)
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = Field(default=None, max_length=32)
    affected_component: Optional[str] = Field(default=None, max_length=512)
    owasp_category: Optional[str] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    source_tool: str = Field(min_length=1, max_length=64)
    raw_source: dict[str, Any] = Field(default_factory=dict)

    # Used by ingest to map finding → asset
    target_hint: Optional[str] = Field(
        default=None,
        description="IP or hostname from scanner output for asset matching",
    )

    @field_validator("cwe_id", mode="before")
    @classmethod
    def normalize_cwe(cls, value: object) -> Optional[str]:
        if value is None or value == "":
            return None
        text = str(value).strip().upper()
        if text.isdigit():
            return f"CWE-{text}"
        if text.startswith("CWE-"):
            return text
        return text

    def compliance_metadata(self) -> dict[str, Any]:
        return {
            "iso_27001": list(self.iso_27001_clause),
            "pci_dss": list(self.pci_dss_requirement),
            "gdpr_risk_flag": self.gdpr_risk_flag,
            "gdpr": ["Art.32"] if self.gdpr_risk_flag else [],
        }
