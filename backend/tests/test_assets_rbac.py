"""Tests for asset endpoint RBAC wiring on the real app."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.deps import get_current_user
from app.core.enums import AssetCriticality, AssetType, UserRole
from app.main import app
from app.schemas.asset import AssetRead
from app.services.asset_service import AssetService
from tests.conftest import make_user


def _asset_read() -> AssetRead:
    return AssetRead(
        id=uuid.uuid4(),
        name="host-1",
        asset_type=AssetType.IP,
        criticality=AssetCriticality.HIGH,
        ip_address="10.0.0.1",
        domain=None,
        cloud_resource_id=None,
        cloud_provider=None,
        is_cde_scope=True,
        hostname=None,
        url=None,
        environment="prod",
        owner=None,
        description=None,
        tags={},
        metadata={},
        created_by_id=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_soc_analyst_cannot_create_asset() -> None:
    analyst = make_user(role=UserRole.SOC_ANALYST)

    async def _user():
        return analyst

    app.dependency_overrides[get_current_user] = _user
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/assets",
                json={
                    "name": "target",
                    "asset_type": "ip",
                    "ip_address": "10.0.0.5",
                },
            )
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_pentester_can_create_asset() -> None:
    pentester = make_user(role=UserRole.PENTESTER, email="pt@example.com")
    asset = _asset_read()

    async def _user():
        return pentester

    async def _create(self, payload, *, created_by_id=None):
        return asset

    app.dependency_overrides[get_current_user] = _user
    original = AssetService.create
    AssetService.create = _create  # type: ignore[method-assign]

    # Also need get_db to not hit real DB — AssetService is constructed with db
    from app.core.database import get_db

    async def _db():
        yield AsyncMock()

    app.dependency_overrides[get_db] = _db

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/assets",
                json={
                    "name": "target",
                    "asset_type": "ip",
                    "ip_address": "10.0.0.5",
                    "is_cde_scope": True,
                },
            )
        assert resp.status_code == 201
        assert resp.json()["name"] == "host-1"
    finally:
        AssetService.create = original  # type: ignore[method-assign]
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_unauthenticated_assets_list_rejected() -> None:
    app.dependency_overrides.clear()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/assets")
    assert resp.status_code == 401
