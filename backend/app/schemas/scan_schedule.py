"""Pydantic schemas for recurring scan schedules."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ScanType, ScannerEngine


class ScanScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    scan_type: ScanType = ScanType.DISCOVERY
    engine: ScannerEngine = ScannerEngine.NMAP
    asset_ids: list[uuid.UUID] = Field(min_length=1)
    config: dict[str, Any] = Field(default_factory=dict)
    interval_minutes: int = Field(default=1440, ge=15, le=10080)
    enabled: bool = True
    run_immediately: bool = False


class ScanScheduleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    scan_type: Optional[ScanType] = None
    engine: Optional[ScannerEngine] = None
    asset_ids: Optional[list[uuid.UUID]] = Field(default=None, min_length=1)
    config: Optional[dict[str, Any]] = None
    interval_minutes: Optional[int] = Field(default=None, ge=15, le=10080)
    enabled: Optional[bool] = None


class ScanScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    scan_type: ScanType
    engine: ScannerEngine
    config: dict[str, Any]
    interval_minutes: int
    enabled: bool
    next_run_at: datetime
    last_run_at: Optional[datetime]
    last_scan_id: Optional[uuid.UUID]
    last_error: Optional[str]
    created_by_id: Optional[uuid.UUID]
    created_at: datetime
    updated_at: datetime
    asset_ids: list[uuid.UUID] = Field(default_factory=list)


class ScanScheduleListResponse(BaseModel):
    items: list[ScanScheduleRead]
    total: int
    page: int
    page_size: int
    pages: int
