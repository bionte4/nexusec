"""Shared pytest fixtures for auth / RBAC tests."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator, Callable
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.config import get_settings
from app.core.deps import get_current_user, require_roles
from app.core.enums import UserRole
from app.core.security import create_access_token, hash_password
from app.main import app as real_app
from app.models.user import User


def make_user(
    *,
    role: UserRole = UserRole.SOC_ANALYST,
    is_active: bool = True,
    email: str = "user@example.com",
    organization_id: uuid.UUID | None = None,
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        full_name="Test User",
        hashed_password=hash_password("SecurePass123!"),
        role=role,
        organization_id=organization_id if organization_id is not None else uuid.uuid4(),
        is_active=is_active,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    return user


@pytest.fixture
def settings():
    get_settings.cache_clear()
    s = get_settings()
    yield s
    get_settings.cache_clear()


@pytest.fixture
def app() -> FastAPI:
    return real_app


@pytest.fixture
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def override_user(app: FastAPI, user: User) -> Callable[[], None]:
    async def _get_user() -> User:
        return user

    app.dependency_overrides[get_current_user] = _get_user

    def _clear() -> None:
        app.dependency_overrides.pop(get_current_user, None)

    return _clear
