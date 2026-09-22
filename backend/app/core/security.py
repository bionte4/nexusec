"""Password hashing and JWT access/refresh token helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import bcrypt
from jose import JWTError, jwt

from app.core.config import get_settings

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"


def hash_password(password: str) -> str:
    """Hash password with bcrypt (72-byte max input enforced)."""
    secret = password.encode("utf-8")[:72]
    return bcrypt.hashpw(secret, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    secret = plain_password.encode("utf-8")[:72]
    try:
        return bcrypt.checkpw(secret, hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _create_token(
    *,
    subject: str,
    token_type: str,
    expires_delta: timedelta,
    extra_claims: Optional[dict[str, Any]] = None,
) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_access_token(
    user_id: UUID,
    role: str,
    *,
    organization_id: Optional[UUID] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    settings = get_settings()
    delta = expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    claims: dict[str, Any] = {"role": role}
    if organization_id is not None:
        claims["org"] = str(organization_id)
    return _create_token(
        subject=str(user_id),
        token_type=TOKEN_TYPE_ACCESS,
        expires_delta=delta,
        extra_claims=claims,
    )


def create_refresh_token(
    user_id: UUID,
    *,
    expires_delta: Optional[timedelta] = None,
) -> str:
    settings = get_settings()
    delta = expires_delta or timedelta(days=settings.refresh_token_expire_days)
    return _create_token(
        subject=str(user_id),
        token_type=TOKEN_TYPE_REFRESH,
        expires_delta=delta,
    )


def decode_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])


def parse_token(token: str, *, expected_type: str) -> dict[str, Any]:
    try:
        payload = decode_token(token)
    except JWTError as exc:
        raise ValueError("Invalid or expired token") from exc

    if payload.get("type") != expected_type:
        raise ValueError(f"Expected {expected_type} token")
    if not payload.get("sub"):
        raise ValueError("Token missing subject")
    return payload
