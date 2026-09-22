"""Pydantic schemas for scan jobs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ScanStatus, ScanType, ScannerEngine


class ScanCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    scan_type: ScanType = ScanType.DISCOVERY
    engine: ScannerEngine = ScannerEngine.NMAP
    asset_ids: list[uuid.UUID] = Field(min_length=1)
    config: dict[str, Any] = Field(default_factory=dict)
    start_immediately: bool = True


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    name: str
    scan_type: ScanType
    engine: ScannerEngine
    status: ScanStatus
    progress: float
    config: dict[str, Any]
    celery_task_id: Optional[str]
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by_id: Optional[uuid.UUID]
    created_at: datetime
    updated_at: datetime
    asset_ids: list[uuid.UUID] = Field(default_factory=list)


class ScanListResponse(BaseModel):
    items: list[ScanRead]
    total: int
    page: int
    page_size: int
    pages: int


class ScanEnqueueResponse(BaseModel):
    scan: ScanRead
    celery_task_id: Optional[str]
    message: str
