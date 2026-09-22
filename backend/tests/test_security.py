"""Unit tests for JWT and password helpers."""

from __future__ import annotations

import uuid

import pytest
from jose import jwt

from app.core.config import get_settings
from app.core.security import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    create_access_token,
    create_refresh_token,
    hash_password,
    parse_token,
    verify_password,
)


def test_password_hash_and_verify() -> None:
    hashed = hash_password("CorrectHorseBattery!")
    assert hashed != "CorrectHorseBattery!"
    assert verify_password("CorrectHorseBattery!", hashed)
    assert not verify_password("wrong-password", hashed)


def test_access_token_contains_role_and_type() -> None:
    user_id = uuid.uuid4()
    token = create_access_token(user_id, "admin")
    settings = get_settings()
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    assert payload["sub"] == str(user_id)
    assert payload["role"] == "admin"
    assert payload["type"] == TOKEN_TYPE_ACCESS


def test_refresh_token_type() -> None:
    user_id = uuid.uuid4()
    token = create_refresh_token(user_id)
    payload = parse_token(token, expected_type=TOKEN_TYPE_REFRESH)
    assert payload["sub"] == str(user_id)


def test_parse_token_rejects_wrong_type() -> None:
    token = create_access_token(uuid.uuid4(), "pentester")
    with pytest.raises(ValueError, match="Expected refresh"):
        parse_token(token, expected_type=TOKEN_TYPE_REFRESH)


def test_parse_token_rejects_tampered() -> None:
    token = create_access_token(uuid.uuid4(), "soc_analyst")
    with pytest.raises(ValueError, match="Invalid"):
        parse_token(token + "x", expected_type=TOKEN_TYPE_ACCESS)
