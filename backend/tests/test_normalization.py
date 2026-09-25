"""Tests for unified vulnerability normalization parsers and fingerprints."""

from __future__ import annotations

from app.core.enums import Severity
from app.normalization.compliance import enrich_compliance
from app.normalization.fingerprint import compute_fingerprint
from app.normalization.parsers.nmap_xml import NmapXmlParser
from app.normalization.parsers.nuclei_json import NucleiJsonParser
from app.normalization.parsers.custom_json import CustomJsonParser
from app.normalization.registry import build_default_registry
from app.normalization.schema import NormalizedFinding

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
        <script id="smb-vuln-ms17-010" output="VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

SAMPLE_NUCLEI_JSONL = """
{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical","description":"JNDI lookup","classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"],"cvss-score":10.0},"tags":["cve","rce"]},"host":"10.0.0.8","matched-at":"http://10.0.0.8:8080","port":"8080"}
{"template-id":"exposed-panel","info":{"name":"Admin Panel","severity":"low","classification":{}},"host":"app.example.com","matched-at":"https://app.example.com/admin"}
""".strip()


def test_nmap_parser_extracts_open_ports_and_scripts() -> None:
    findings = NmapXmlParser().parse(SAMPLE_NMAP_XML)
    assert findings
    ports = {f.port for f in findings}
    assert 22 in ports
    assert 445 in ports
    assert 80 not in ports  # closed
    assert all(f.target_hint == "10.0.0.8" for f in findings)
    assert all(f.source_tool == "nmap" for f in findings)
    script_hits = [f for f in findings if "smb-vuln" in f.vuln_id]
    assert script_hits
    assert script_hits[0].severity == Severity.HIGH


def test_nuclei_parser_jsonl() -> None:
    findings = NucleiJsonParser().parse(SAMPLE_NUCLEI_JSONL)
    assert len(findings) == 2
    critical = findings[0]
    assert critical.severity == Severity.CRITICAL
    assert critical.cve_id == "CVE-2021-44228"
    assert critical.cwe_id == "CWE-502"
    assert critical.cvss_score == 10.0
    assert critical.name == "Log4j RCE"
    assert findings[1].target_hint == "app.example.com"


def test_custom_parser_and_schema_fields() -> None:
    raw = {
        "findings": [
            {
                "vuln_id": "custom-1",
                "name": "PII exposure via API",
                "description": "Endpoint leaks email",
                "severity": "high",
                "cvss_score": 7.5,
                "cwe_id": "200",
                "mitre_tactics": ["T1530"],
                "remediation_steps": "Remove PII from response",
                "iso_27001_clause": ["A.8.12"],
                "pci_dss_requirement": ["3.4"],
                "gdpr_risk_flag": True,
                "source_tool": "nexusec",
            }
        ]
    }
    findings = CustomJsonParser().parse(raw)
    assert len(findings) == 1
    f = enrich_compliance(findings[0])
    assert f.cwe_id == "CWE-200"
    assert f.gdpr_risk_flag is True
    meta = f.compliance_metadata()
    assert "A.8.12" in meta["iso_27001"]
    assert meta["gdpr_risk_flag"] is True
    assert meta["nist_csf"]
    assert meta["nist_800_53"]


def test_fingerprint_stable_and_asset_scoped() -> None:
    f = NormalizedFinding(
        vuln_id="x",
        name="Open port tcp/22",
        source_tool="nmap",
        port=22,
        protocol="tcp",
    )
    a = compute_fingerprint(f, asset_key="asset-1")
    b = compute_fingerprint(f, asset_key="asset-1")
    c = compute_fingerprint(f, asset_key="asset-2")
    assert a == b
    assert len(a) == 64
    assert a != c


def test_registry_has_expected_parsers() -> None:
    reg = build_default_registry()
    assert set(reg.available()) >= {"nmap", "nuclei", "nexusec", "openvas"}


def test_enrich_adds_defaults() -> None:
    f = NormalizedFinding(
        vuln_id="1",
        name="Open SSH",
        source_tool="nmap",
        port=22,
        severity=Severity.INFO,
    )
    enriched = enrich_compliance(f)
    assert enriched.iso_27001_clause
    assert enriched.pci_dss_requirement
    assert enriched.mitre_tactics
    assert enriched.remediation_steps
    assert "PR.AA-01" in enriched.nist_csf or "ID.RA-01" in enriched.nist_csf
    assert "RA-5" in enriched.nist_800_53 or "AC-2" in enriched.nist_800_53
    meta = enriched.compliance_metadata()
    assert meta["nist_csf"]
    assert meta["nist_800_53"]


def test_enrich_nist_tls_and_web_heuristics() -> None:
    tls = enrich_compliance(
        NormalizedFinding(
            vuln_id="tls",
            name="Weak TLS cipher suite",
            description="Outdated certificate cipher",
            source_tool="nuclei",
            severity=Severity.MEDIUM,
        )
    )
    assert "PR.DS-02" in tls.nist_csf
    assert "SC-8" in tls.nist_800_53

    web = enrich_compliance(
        NormalizedFinding(
            vuln_id="web",
            name="SQL injection on login",
            description="CVE-2024-0001 XSS/SQLi candidate",
            source_tool="nuclei",
            port=443,
            severity=Severity.HIGH,
        )
    )
    assert web.nist_csf
    assert "RA-5" in web.nist_800_53
