"""Authentication request/response schemas."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field

from app.core.enums import UserRole
from app.schemas import UserRead


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str


class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=128)
    role: UserRole = UserRole.SOC_ANALYST


class AuthUserRead(UserRead):
    """Authenticated user profile (same shape as UserRead)."""


class LoginResponse(TokenPair):
    user: AuthUserRead
