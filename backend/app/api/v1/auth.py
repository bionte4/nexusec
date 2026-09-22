"""Authentication endpoints: register, login, refresh, me."""

from __future__ import annotations

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireAdmin, RequireAnyAuthenticated, get_current_user_optional
from app.core.enums import UserRole
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
)
from app.schemas import UserListResponse, UserRead
from app.services.auth_service import AuthError, AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register user (first user becomes Admin)",
)
async def register(
    payload: RegisterRequest,
    service: AuthService = Depends(get_auth_service),
    actor: Annotated[Optional[User], Depends(get_current_user_optional)] = None,
) -> UserRead:
    try:
        return await service.register(payload, actor=actor)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login with email/password (JSON or form)",
)
async def login_json(
    payload: LoginRequest,
    service: AuthService = Depends(get_auth_service),
) -> LoginResponse:
    try:
        return await service.login(payload.email, payload.password)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/login/form",
    response_model=LoginResponse,
    summary="OAuth2 password form login (Swagger Authorize)",
)
async def login_form(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    service: AuthService = Depends(get_auth_service),
) -> LoginResponse:
    """OAuth2 password form compatible with Swagger Authorize."""
    try:
        return await service.login(form_data.username, form_data.password)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/refresh",
    response_model=TokenPair,
    summary="Refresh access token",
)
async def refresh(
    payload: RefreshRequest,
    service: AuthService = Depends(get_auth_service),
) -> TokenPair:
    try:
        return await service.refresh(payload.refresh_token)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get(
    "/me",
    response_model=UserRead,
    summary="Current authenticated user",
)
async def me(current_user: RequireAnyAuthenticated) -> UserRead:
    return UserRead.model_validate(current_user)


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List users (Admin / Super Admin)",
)
async def list_users(
    current_user: RequireAdmin,
    service: AuthService = Depends(get_auth_service),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None),
) -> UserListResponse:
    try:
        return await service.list_users(
            actor=current_user,
            page=page,
            page_size=page_size,
            search=search,
        )
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get(
    "/roles",
    summary="List available RBAC roles",
)
async def list_roles(_: RequireAnyAuthenticated) -> dict[str, list[str]]:
    return {"roles": [role.value for role in UserRole]}
