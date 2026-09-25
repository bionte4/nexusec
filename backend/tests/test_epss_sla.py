"""Tests for EPSS parsing and remediation SLA helpers."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.core.enums import Severity
from app.services.sla import compute_remediation_due_at, sla_days_for_severity
from app.services.threat_intel.epss_client import parse_epss_payload


def test_parse_epss_payload() -> None:
    scores = parse_epss_payload(
        {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.97542",
                    "percentile": "0.99989",
                    "date": "2024-06-01",
                },
                {"cve": "bad", "epss": "0.1", "percentile": "0.2"},
            ],
        }
    )
    assert len(scores) == 1
    assert scores[0].cve_id == "CVE-2021-44228"
    assert scores[0].epss == pytest.approx(0.97542)
    assert scores[0].percentile == pytest.approx(0.99989)


def test_sla_days_critical_shorter_than_low() -> None:
    assert sla_days_for_severity(Severity.CRITICAL) < sla_days_for_severity(Severity.LOW)


def test_compute_remediation_due_at_adds_days() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    due = compute_remediation_due_at(Severity.CRITICAL, from_time=start)
    assert due > start
    delta = (due - start).days
    assert delta == sla_days_for_severity(Severity.CRITICAL)
