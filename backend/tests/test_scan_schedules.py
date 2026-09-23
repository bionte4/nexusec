"""Tests for scan schedule schemas and interval bounds."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.core.enums import ScanType, ScannerEngine
from app.schemas.scan_schedule import ScanScheduleCreate


def test_schedule_create_defaults() -> None:
    payload = ScanScheduleCreate(name="Daily nmap", asset_ids=[uuid.uuid4()])
    assert payload.interval_minutes == 1440
    assert payload.engine == ScannerEngine.NMAP
    assert payload.scan_type == ScanType.DISCOVERY
    assert payload.enabled is True
    assert payload.run_immediately is False


def test_schedule_interval_bounds() -> None:
    with pytest.raises(ValidationError):
        ScanScheduleCreate(
            name="too fast",
            asset_ids=[uuid.uuid4()],
            interval_minutes=5,
        )
    with pytest.raises(ValidationError):
        ScanScheduleCreate(
            name="too slow",
            asset_ids=[uuid.uuid4()],
            interval_minutes=20000,
        )
