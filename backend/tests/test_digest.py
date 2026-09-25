"""Unit tests for SOC digest payloads and aggregation helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

from app.core.enums import FindingStatus, Severity
from app.services.digest_service import (
    DigestService,
    build_digest_generic_payload,
    build_digest_slack_payload,
)


def test_build_digest_slack_payload_contains_counts() -> None:
    payload = build_digest_slack_payload(
        {
            "generated_at": "2026-01-01T00:00:00Z",
            "organization_id": None,
            "overdue_count": 3,
            "open_critical": 1,
            "open_high": 2,
            "active_total": 10,
            "top_findings": [
                {
                    "severity": "critical",
                    "title": "RCE",
                    "asset_name": "web-1",
                }
            ],
        }
    )
    assert "overdue=3" in payload["text"]
    assert "NexuSec daily digest" in payload["blocks"][0]["text"]["text"]


def test_build_digest_generic_event_type() -> None:
    body = build_digest_generic_payload({"overdue_count": 0})
    assert body["event"] == "nexusec.digest"


def test_digest_service_build_counts(monkeypatch) -> None:
    now = datetime.now(timezone.utc)
    overdue = MagicMock()
    overdue.id = uuid4()
    overdue.title = "Old SSH"
    overdue.severity = Severity.HIGH
    overdue.status = FindingStatus.OPEN
    overdue.remediation_due_at = now - timedelta(days=2)
    overdue.threat_risk_score = 80.0
    overdue.asset = MagicMock(name="host-a")
    overdue.asset.name = "host-a"
    overdue.asset_id = uuid4()

    session = MagicMock()

    def scalar(stmt):  # noqa: ANN001
        # crude: return different counts based on call order
        if not hasattr(scalar, "n"):
            scalar.n = 0  # type: ignore[attr-defined]
        scalar.n += 1  # type: ignore[attr-defined]
        return {1: 5, 2: 1, 3: 2, 4: 1}.get(scalar.n, 0)  # type: ignore[attr-defined]

    session.scalar.side_effect = scalar
    session.scalars.return_value.all.return_value = [overdue]

    digest = DigestService(session).build_digest()
    assert digest["active_total"] == 5
    assert digest["open_critical"] == 1
    assert digest["open_high"] == 2
    assert digest["overdue_count"] == 1
    assert digest["top_findings"][0]["title"] == "Old SSH"
    assert digest["top_findings"][0]["overdue"] is True


def test_send_digest_skipped_when_disabled(monkeypatch) -> None:
    settings = MagicMock()
    settings.digest_enabled = False
    session = MagicMock()
    svc = DigestService(session, settings=settings)
    out = svc.send_digest({"overdue_count": 1})
    assert out[0]["skipped"] is True
