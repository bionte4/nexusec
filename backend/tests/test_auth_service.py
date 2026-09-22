"""Auth service unit tests (no database)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.enums import UserRole
from app.core.security import create_refresh_token, hash_password, verify_password
from app.models.user import User
from app.schemas.auth import RegisterRequest
from app.services.auth_service import AuthError, AuthService


def _user(role: UserRole = UserRole.SOC_ANALYST, password: str = "SecurePass123!") -> User:
    return User(
        id=uuid.uuid4(),
        email="user@example.com",
        full_name="User",
        hashed_password=hash_password(password),
        role=role,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_login_success() -> None:
    user = _user(password="SecurePass123!")
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=user)
    db.get = AsyncMock(return_value=user)

    service = AuthService(db)
    result = await service.login("user@example.com", "SecurePass123!")
    assert result.access_token
    assert result.refresh_token
    assert result.user.email == "user@example.com"


@pytest.mark.asyncio
async def test_login_wrong_password() -> None:
    user = _user(password="SecurePass123!")
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=user)
    service = AuthService(db)
    with pytest.raises(AuthError) as exc:
        await service.login("user@example.com", "wrong-password")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_register_first_user_becomes_admin() -> None:
    db = MagicMock()
    db.scalar = AsyncMock(side_effect=[None, 0])
    db.flush = AsyncMock()
    db.refresh = AsyncMock()
    created: list[User] = []

    def _add(obj: User) -> None:
        obj.id = uuid.uuid4()
        obj.created_at = datetime.now(timezone.utc)
        obj.updated_at = datetime.now(timezone.utc)
        created.append(obj)

    db.add.side_effect = _add

    service = AuthService(db)
    payload = RegisterRequest(
        email="first@example.com",
        full_name="First Admin",
        password="SecurePass123!",
        role=UserRole.SOC_ANALYST,
    )
    user_read = await service.register(payload, actor=None)
    assert created[0].role == UserRole.ADMIN
    assert user_read.role == UserRole.ADMIN


@pytest.mark.asyncio
async def test_register_non_admin_forced_to_soc_analyst() -> None:
    db = MagicMock()
    db.scalar = AsyncMock(side_effect=[None, 5])
    db.flush = AsyncMock()
    db.refresh = AsyncMock()
    created: list[User] = []

    def _add(obj: User) -> None:
        obj.id = uuid.uuid4()
        obj.created_at = datetime.now(timezone.utc)
        obj.updated_at = datetime.now(timezone.utc)
        created.append(obj)

    db.add.side_effect = _add

    actor = _user(role=UserRole.PENTESTER)
    service = AuthService(db)
    payload = RegisterRequest(
        email="new@example.com",
        full_name="New User",
        password="SecurePass123!",
        role=UserRole.ADMIN,
    )
    result = await service.register(payload, actor=actor)
    assert created[0].role == UserRole.SOC_ANALYST
    assert result.role == UserRole.SOC_ANALYST


@pytest.mark.asyncio
async def test_refresh_issues_new_pair() -> None:
    user = _user(role=UserRole.ADMIN)
    refresh = create_refresh_token(user.id)
    db = AsyncMock()
    db.get = AsyncMock(return_value=user)
    service = AuthService(db)
    tokens = await service.refresh(refresh)
    assert tokens.access_token
    assert tokens.refresh_token


@pytest.mark.asyncio
async def test_refresh_invalid_token() -> None:
    service = AuthService(AsyncMock())
    with pytest.raises(AuthError) as exc:
        await service.refresh("not-a-token")
    assert exc.value.status_code == 401


def test_verify_password_roundtrip() -> None:
    assert verify_password("abc123!@#XYZ", hash_password("abc123!@#XYZ"))
