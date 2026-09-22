"""Authentication business logic with organization bootstrap."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import UserRole
from app.core.security import (
    TOKEN_TYPE_REFRESH,
    create_access_token,
    create_refresh_token,
    hash_password,
    parse_token,
    verify_password,
)
from app.models.organization import Organization
from app.models.user import User
from app.schemas.auth import LoginResponse, RegisterRequest, TokenPair
from app.schemas import UserRead


class AuthError(Exception):
    """Authentication / authorization domain error."""

    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class AuthService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def register(
        self,
        payload: RegisterRequest,
        *,
        actor: Optional[User] = None,
    ) -> UserRead:
        existing = await self.db.scalar(
            select(User).where(func.lower(User.email) == payload.email.lower())
        )
        if existing is not None:
            raise AuthError("Email already registered", status_code=409)

        user_count = int(await self.db.scalar(select(func.count()).select_from(User)) or 0)
        requested_role = payload.role

        if user_count == 0:
            # Bootstrap: first user is Super Admin + default organization
            org = await self._ensure_default_organization()
            role = UserRole.SUPER_ADMIN
            organization_id = org.id
        elif actor is None:
            raise AuthError(
                "Registration requires an invite from an Admin",
                status_code=403,
            )
        elif actor.role == UserRole.SUPER_ADMIN:
            if requested_role == UserRole.SUPER_ADMIN:
                role = UserRole.SUPER_ADMIN
                organization_id = payload.organization_id  # may be None (platform)
            else:
                role = requested_role
                organization_id = payload.organization_id or actor.organization_id
                if organization_id is None:
                    raise AuthError(
                        "organization_id is required when Super Admin registers tenant users",
                        status_code=400,
                    )
        elif actor.role == UserRole.ADMIN:
            # Org admin can only add users to their own tenant
            role = (
                requested_role
                if requested_role
                in {UserRole.ADMIN, UserRole.PENTESTER, UserRole.SOC_ANALYST}
                else UserRole.SOC_ANALYST
            )
            if role == UserRole.SUPER_ADMIN:
                raise AuthError("Cannot assign super_admin role", status_code=403)
            organization_id = actor.organization_id
            if organization_id is None:
                raise AuthError("Admin has no organization", status_code=400)
        else:
            raise AuthError("Only Admins can register users", status_code=403)

        if organization_id is not None:
            org = await self.db.get(Organization, organization_id)
            if org is None or not org.is_active:
                raise AuthError("Organization not found or inactive", status_code=400)

        user = User(
            email=payload.email.lower(),
            full_name=payload.full_name,
            hashed_password=hash_password(payload.password),
            role=role,
            organization_id=organization_id,
            is_active=True,
        )
        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)
        return UserRead.model_validate(user)

    async def login(self, email: str, password: str) -> LoginResponse:
        user = await self.db.scalar(select(User).where(func.lower(User.email) == email.lower()))
        if user is None or not verify_password(password, user.hashed_password):
            raise AuthError("Incorrect email or password", status_code=401)
        if not user.is_active:
            raise AuthError("User account is inactive", status_code=403)

        tokens = self._issue_tokens(user)
        return LoginResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type=tokens.token_type,
            user=UserRead.model_validate(user),
        )

    async def refresh(self, refresh_token: str) -> TokenPair:
        try:
            payload = parse_token(refresh_token, expected_type=TOKEN_TYPE_REFRESH)
            user_id = UUID(str(payload["sub"]))
        except (ValueError, TypeError) as exc:
            raise AuthError("Invalid refresh token", status_code=401) from exc

        user = await self.db.get(User, user_id)
        if user is None or not user.is_active:
            raise AuthError("Invalid refresh token", status_code=401)
        return self._issue_tokens(user)

    async def _ensure_default_organization(self) -> Organization:
        existing = await self.db.scalar(
            select(Organization).where(Organization.slug == "default")
        )
        if existing is not None:
            return existing
        org = Organization(
            name="Default Organization",
            slug="default",
            description="Bootstrap platform organization",
            is_active=True,
            settings={},
        )
        self.db.add(org)
        await self.db.flush()
        await self.db.refresh(org)
        return org

    @staticmethod
    def _issue_tokens(user: User) -> TokenPair:
        return TokenPair(
            access_token=create_access_token(
                user.id,
                user.role.value,
                organization_id=user.organization_id,
            ),
            refresh_token=create_refresh_token(user.id),
        )
