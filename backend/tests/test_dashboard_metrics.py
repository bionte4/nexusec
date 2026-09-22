"""Pure unit tests for dashboard risk scoring helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.enums import ACTIVE_FINDING_STATUSES, FindingStatus, Severity
from app.services.dashboard_service import DashboardService, _RISK_WEIGHTS


def test_active_statuses_include_in_progress() -> None:
    assert FindingStatus.IN_PROGRESS in ACTIVE_FINDING_STATUSES
    assert FindingStatus.RESOLVED not in ACTIVE_FINDING_STATUSES
    assert FindingStatus.FALSE_POSITIVE not in ACTIVE_FINDING_STATUSES


def test_risk_weights_cover_dashboard_severities() -> None:
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        assert sev in _RISK_WEIGHTS
        assert _RISK_WEIGHTS[sev] > 0


@pytest.mark.asyncio
async def test_active_by_severity_aggregates_rows() -> None:
    db = AsyncMock()
    result = MagicMock()
    result.all.return_value = [
        (Severity.CRITICAL, 2),
        (Severity.HIGH, 5),
        (Severity.MEDIUM, 1),
    ]
    db.execute = AsyncMock(return_value=result)
    service = DashboardService(db)
    counts = await service.active_by_severity()
    assert counts.critical == 2
    assert counts.high == 5
    assert counts.medium == 1
    assert counts.low == 0
    assert counts.total == 8


@pytest.mark.asyncio
async def test_asset_risk_posture_ranks_by_score() -> None:
    asset_a = uuid.uuid4()
    asset_b = uuid.uuid4()
    db = AsyncMock()
    result = MagicMock()
    result.all.return_value = [
        (asset_a, "web", "domain", False, "high", Severity.MEDIUM, 3),
        (asset_b, "dc01", "ip", True, "critical", Severity.CRITICAL, 1),
        (asset_b, "dc01", "ip", True, "critical", Severity.HIGH, 2),
    ]
    db.execute = AsyncMock(return_value=result)
    service = DashboardService(db)
    rows = await service.asset_risk_posture(limit=10)
    assert rows[0].asset_id == asset_b
    assert rows[0].active_critical == 1
    assert rows[0].active_high == 2
    assert rows[0].risk_score > rows[1].risk_score
