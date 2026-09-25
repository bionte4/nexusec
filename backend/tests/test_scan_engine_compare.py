"""Unit tests for scan soft-match keys used in cross-engine comparison."""

from __future__ import annotations

from app.core.enums import Severity
from app.normalization.schema import NormalizedFinding
from app.services.scan_diff_service import soft_match_key


def test_soft_match_prefers_cve() -> None:
    a = NormalizedFinding(
        vuln_id="a",
        name="TLS weak ciphers",
        source_tool="openvas",
        severity=Severity.HIGH,
        cve_id="CVE-2016-2183",
        port=443,
    )
    b = NormalizedFinding(
        vuln_id="b",
        name="Different title same CVE",
        source_tool="nuclei",
        severity=Severity.CRITICAL,
        cve_id="cve-2016-2183",
        port=8443,
    )
    assert soft_match_key(a) == soft_match_key(b)
    assert soft_match_key(a).startswith("cve:")


def test_soft_match_falls_back_to_port_title() -> None:
    a = NormalizedFinding(
        vuln_id="a",
        name="Open SSH",
        source_tool="nmap",
        severity=Severity.INFO,
        port=22,
        protocol="tcp",
    )
    b = NormalizedFinding(
        vuln_id="b",
        name="open  ssh",
        source_tool="nexusec",
        severity=Severity.INFO,
        port=22,
        protocol="tcp",
    )
    assert soft_match_key(a) == soft_match_key(b)
    assert soft_match_key(a).startswith("loc:")
