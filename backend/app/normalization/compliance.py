"""Default compliance / MITRE / NIST enrichment heuristics for normalized findings."""

from __future__ import annotations

from app.core.enums import Severity
from app.normalization.schema import NormalizedFinding

# Baseline control mappings commonly cited for VA findings
_DEFAULT_ISO = ["A.8.8"]  # Management of technical vulnerabilities
_DEFAULT_PCI = ["11.3.1"]  # Internal vulnerability scans

# NIST CSF 2.0 category examples + SP 800-53 Rev.5 baselines for VA findings
_DEFAULT_NIST_CSF = ["ID.RA-01", "PR.PS-02"]
_DEFAULT_NIST_800_53 = ["RA-5", "SI-2"]


def enrich_compliance(finding: NormalizedFinding) -> NormalizedFinding:
    """Fill empty compliance / MITRE / NIST fields with safe defaults."""
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

    if not data.nist_csf or not data.nist_800_53:
        csf, sp = _nist_for_finding(data)
        if not data.nist_csf:
            data.nist_csf = csf
        if not data.nist_800_53:
            data.nist_800_53 = sp

    if not data.mitre_tactics:
        data.mitre_tactics = _default_mitre(data)

    if not data.remediation_steps:
        data.remediation_steps = (
            "Review the affected service, apply vendor patches, "
            "restrict exposure, and re-scan to verify remediation."
        )

    return data


def _nist_for_finding(finding: NormalizedFinding) -> tuple[list[str], list[str]]:
    """Heuristic NIST CSF + 800-53 mapping from finding context."""
    name = finding.name.lower()
    desc = (finding.description or "").lower()
    blob = f"{name} {desc} {finding.cwe_id or ''} {finding.affected_component or ''}".lower()
    port = finding.port

    # Network exposure / open ports → Protect / Identify
    if "open port" in name or port in {21, 23, 445, 3389, 5900}:
        return (
            ["ID.RA-01", "PR.IR-01", "PR.AA-01"],
            ["RA-5", "CM-7", "AC-3", "SC-7"],
        )
    if port in {80, 443, 8080, 8443} or "http" in blob or "web" in blob:
        return (
            ["ID.RA-01", "PR.PS-02", "DE.CM-01"],
            ["RA-5", "SI-2", "SI-10", "SC-7"],
        )
    if "ssh" in blob or port == 22:
        return (
            ["PR.AA-01", "PR.PS-01", "ID.RA-01"],
            ["AC-2", "AC-3", "IA-2", "RA-5"],
        )
    if any(k in blob for k in ("ssl", "tls", "certificate", "cipher")):
        return (
            ["PR.DS-02", "PR.PS-01", "ID.RA-01"],
            ["SC-8", "SC-12", "SC-13", "RA-5"],
        )
    if any(k in blob for k in ("pii", "gdpr", "leak", "disclosure", "sensitive")):
        return (
            ["PR.DS-01", "PR.DS-02", "ID.RA-01"],
            ["SI-4", "SC-7", "MP-6", "RA-5"],
        )
    if any(k in blob for k in ("cve-", "vuln", "rce", "injection", "xss", "sqli")):
        return (
            ["ID.RA-01", "PR.PS-02", "RS.MI-01"],
            ["RA-5", "SI-2", "CM-6"],
        )
    return list(_DEFAULT_NIST_CSF), list(_DEFAULT_NIST_800_53)


def _default_mitre(finding: NormalizedFinding) -> list[str]:
    name = finding.name.lower()
    if "ssh" in name or finding.port == 22:
        return ["TA0001", "T1021"]  # Initial Access / Remote Services
    if finding.port in {80, 443, 8080, 8443} or "http" in name:
        return ["TA0001", "T1190"]  # Exploit Public-Facing Application
    if "smb" in name or finding.port in {139, 445}:
        return ["TA0008", "T1021.002"]
    return ["TA0043"]  # Reconnaissance (discovery-style findings)
