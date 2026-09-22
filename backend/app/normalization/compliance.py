"""Default compliance / MITRE enrichment heuristics for normalized findings."""

from __future__ import annotations

from app.core.enums import Severity
from app.normalization.schema import NormalizedFinding

# Baseline control mappings commonly cited for VA findings
_DEFAULT_ISO = ["A.8.8"]  # Management of technical vulnerabilities
_DEFAULT_PCI = ["11.3.1"]  # Internal vulnerability scans


def enrich_compliance(finding: NormalizedFinding) -> NormalizedFinding:
    """Fill empty compliance / MITRE fields with safe defaults."""
    data = finding.model_copy(deep=True)

    if not data.iso_27001_clause:
        data.iso_27001_clause = list(_DEFAULT_ISO)
    if not data.pci_dss_requirement:
        data.pci_dss_requirement = list(_DEFAULT_PCI)

    # GDPR: treat high+ findings with PII-ish keywords as risk
    blob = f"{data.name} {data.description or ''}".lower()
    pii_keywords = ("pii", "personal data", "gdpr", "email", "password", "ssn")
    if data.gdpr_risk_flag is False and any(k in blob for k in pii_keywords):
        if data.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}:
            data.gdpr_risk_flag = True

    if not data.mitre_tactics:
        data.mitre_tactics = _default_mitre(data)

    if not data.remediation_steps:
        data.remediation_steps = (
            "Review the affected service, apply vendor patches, "
            "restrict exposure, and re-scan to verify remediation."
        )

    return data


def _default_mitre(finding: NormalizedFinding) -> list[str]:
    name = finding.name.lower()
    if "ssh" in name or finding.port == 22:
        return ["TA0001", "T1021"]  # Initial Access / Remote Services
    if finding.port in {80, 443, 8080, 8443} or "http" in name:
        return ["TA0001", "T1190"]  # Exploit Public-Facing Application
    if "smb" in name or finding.port in {139, 445}:
        return ["TA0008", "T1021.002"]
    return ["TA0043"]  # Reconnaissance (discovery-style findings)
