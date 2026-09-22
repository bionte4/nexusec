"""Authentication business logic with organization bootstrap."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from sqlalchemy import func, or_, select
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
from app.schemas import UserListResponse, UserRead
from app.schemas.auth import LoginResponse, RegisterRequest, TokenPair


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

    async def list_users(
        self,
        *,
        actor: User,
        page: int = 1,
        page_size: int = 20,
        search: str | None = None,
    ) -> UserListResponse:
        """List users visible to the actor (tenant-scoped for Admin)."""
        filters = []
        if actor.role == UserRole.SUPER_ADMIN:
            pass
        elif actor.role == UserRole.ADMIN:
            if actor.organization_id is None:
                raise AuthError("Admin has no organization", status_code=400)
            filters.append(User.organization_id == actor.organization_id)
        else:
            raise AuthError("Only Admins can list users", status_code=403)

        if search:
            term = f"%{search.strip().lower()}%"
            filters.append(
                or_(
                    func.lower(User.email).like(term),
                    func.lower(User.full_name).like(term),
                )
            )

        count_stmt = select(func.count()).select_from(User)
        list_stmt = select(User).order_by(User.created_at.desc())
        for f in filters:
            count_stmt = count_stmt.where(f)
            list_stmt = list_stmt.where(f)

        total = int(await self.db.scalar(count_stmt) or 0)
        pages = max(1, (total + page_size - 1) // page_size) if total else 1
        offset = (page - 1) * page_size
        rows = (
            await self.db.scalars(list_stmt.offset(offset).limit(page_size))
        ).all()
        return UserListResponse(
            items=[UserRead.model_validate(u) for u in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
        )

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
