"""Unit tests for NIST control mapping suggestions (heuristic path)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.core.enums import FindingStatus, Severity
from app.models.vulnerability import Vulnerability
from app.services.nist_mapping_service import _heuristic_suggestion


def _vuln(**kwargs: object) -> Vulnerability:
    now = datetime.now(timezone.utc)
    defaults = dict(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        fingerprint=uuid.uuid4().hex,
        title="Open port tcp/22 (ssh)",
        description="SSH service exposed",
        severity=Severity.INFO,
        status=FindingStatus.OPEN,
        evidence={},
        mitre_attack_techniques=[],
        compliance_metadata={},
        raw_source={},
        source_tool="nmap",
        port=22,
        protocol="tcp",
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    defaults.update(kwargs)
    return Vulnerability(**defaults)  # type: ignore[arg-type]


def test_heuristic_maps_ssh_to_access_controls() -> None:
    suggestion = _heuristic_suggestion(_vuln())
    assert suggestion["provider"] == "heuristic"
    assert "PR.AA-01" in suggestion["nist_csf"] or "ID.RA-01" in suggestion["nist_csf"]
    assert any(c.startswith("AC-") or c == "RA-5" for c in suggestion["nist_800_53"])
    assert "Review" in suggestion["reasoning"]


def test_heuristic_maps_web_injection() -> None:
    suggestion = _heuristic_suggestion(
        _vuln(
            title="Reflected XSS on search",
            description="CVE-2023-9999 injection candidate",
            severity=Severity.HIGH,
            port=443,
        )
    )
    assert suggestion["nist_csf"]
    assert "RA-5" in suggestion["nist_800_53"]
