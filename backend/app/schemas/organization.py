"""Organization / tenant API schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: Optional[str] = Field(default=None, max_length=64)
    description: Optional[str] = None
    settings: dict[str, Any] = Field(default_factory=dict)


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=255)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    settings: Optional[dict[str, Any]] = None


class OrganizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    description: Optional[str] = None
    is_active: bool
    workspace_token_prefix: Optional[str] = None
    workspace_token: Optional[str] = None  # only on create/rotate
    settings: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class OrganizationListResponse(BaseModel):
    items: list[OrganizationRead]
    total: int
    page: int
    page_size: int
    pages: int


class WorkspaceTokenResponse(BaseModel):
    organization_id: uuid.UUID
    workspace_token: str
    workspace_token_prefix: str


class OrganizationMetrics(BaseModel):
    organization_id: uuid.UUID
    users: int
    assets: int
    scans: int
    open_vulnerabilities: int
    critical_open: int
    actively_exploited: int
    cde_assets: int
