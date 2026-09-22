"""Tests for CISA KEV / NVD threat intelligence enrichment."""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock, patch

from app.core.enums import Severity
from app.services.threat_intel.enrichment import (
    ThreatIntelService,
    compute_threat_risk_score,
    normalize_cve_id,
)
from app.services.threat_intel.kev_client import parse_kev_catalog
from app.services.threat_intel.nvd_client import detect_public_exploits, parse_nvd_response


SAMPLE_KEV = {
    "catalogVersion": "2024.01",
    "dateReleased": "2024-01-01T00:00:00Z",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "requiredAction": "Apply updates",
            "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
        {
            "cveID": "NOT-A-CVE",
            "vendorProject": "x",
            "product": "y",
            "vulnerabilityName": "bad",
            "dateAdded": "2020-01-01",
            "dueDate": "2020-01-02",
            "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "",
            "notes": "",
        },
    ],
}


def test_normalize_cve_id() -> None:
    assert normalize_cve_id("cve-2021-44228") == "CVE-2021-44228"
    assert normalize_cve_id(None) is None
    assert normalize_cve_id("  ") is None


def test_parse_kev_catalog() -> None:
    entries = parse_kev_catalog(SAMPLE_KEV)
    assert len(entries) == 1
    assert entries[0].cve_id == "CVE-2021-44228"
    assert entries[0].date_added == date(2021, 12, 10)
    assert entries[0].known_ransomware_use == "Known"


def test_compute_threat_risk_score_kev_boost() -> None:
    base = compute_threat_risk_score(
        severity=Severity.HIGH,
        cvss_score=7.5,
        in_kev=False,
        has_public_exploit=False,
    )
    boosted = compute_threat_risk_score(
        severity=Severity.HIGH,
        cvss_score=7.5,
        in_kev=True,
        has_public_exploit=True,
        known_ransomware_use="Known",
    )
    assert boosted > base
    assert boosted == 100.0  # capped


def test_detect_public_exploits() -> None:
    item = {
        "cve": {
            "references": [
                {
                    "url": "https://www.exploit-db.com/exploits/12345",
                    "tags": ["Third Party Advisory"],
                },
                {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]},
            ]
        }
    }
    has_exploit, refs = detect_public_exploits(item)
    assert has_exploit is True
    assert any("exploit-db" in r for r in refs)


def test_parse_nvd_response() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {"baseScore": 10.0},
                                "exploitabilityScore": 3.9,
                            }
                        ]
                    },
                    "references": [
                        {"url": "https://github.com/foo/poc", "tags": ["Exploit"]},
                    ],
                }
            }
        ]
    }
    result = parse_nvd_response(payload, "CVE-2021-44228")
    assert result is not None
    assert result.cvss_score == 10.0
    assert result.has_public_exploit is True


def test_upsert_kev_and_enrich_vulnerability() -> None:
    from app.models.threat_intel import ThreatIntelCve
    from app.models.vulnerability import Vulnerability
    from app.services.threat_intel.kev_client import parse_kev_catalog

    session = MagicMock()
    stored: dict[str, ThreatIntelCve] = {}

    def get_side_effect(model, key):
        if model is ThreatIntelCve:
            return stored.get(key)
        return None

    session.get.side_effect = get_side_effect

    def add_side_effect(obj):
        if isinstance(obj, ThreatIntelCve):
            stored[obj.cve_id] = obj

    session.add.side_effect = add_side_effect

    svc = ThreatIntelService(session)
    entries = parse_kev_catalog(SAMPLE_KEV)
    count = svc.upsert_kev_entries(entries)
    assert count == 1
    assert stored["CVE-2021-44228"].in_kev is True

    vuln = Vulnerability(
        title="Log4Shell",
        fingerprint="fp1",
        severity=Severity.MEDIUM,
        cve_id="CVE-2021-44228",
        cvss_score=8.0,
    )
    # Minimal required fields skipped for unit mock — set attrs used by enrich
    session.scalars.return_value.all.return_value = [vuln]

    with patch(
        "app.services.threat_intel.enrichment.fetch_nvd_cve",
        return_value=None,
    ):
        result = svc.enrich_vulnerabilities(limit=10, fetch_nvd=False)

    assert result["vulnerabilities_enriched"] == 1
    assert vuln.is_actively_exploited is True
    assert vuln.threat_risk_score is not None
    assert vuln.threat_risk_score >= 75.0
    assert vuln.threat_intel_metadata.get("in_kev") is True
