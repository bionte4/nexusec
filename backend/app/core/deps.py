"""FastAPI dependencies for authentication and RBAC."""

from __future__ import annotations

from typing import Annotated, Callable, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.enums import UserRole
from app.core.security import TOKEN_TYPE_ACCESS, parse_token
from app.models.user import User

settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_v1_prefix}/auth/login/form",
    auto_error=True,
)

oauth2_scheme_optional = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_v1_prefix}/auth/login/form",
    auto_error=False,
)


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = parse_token(token, expected_type=TOKEN_TYPE_ACCESS)
        user_id = UUID(str(payload["sub"]))
    except (ValueError, TypeError) as exc:
        raise credentials_exception from exc

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise credentials_exception
    return user


async def get_current_user_optional(
    token: Annotated[Optional[str], Depends(oauth2_scheme_optional)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Optional[User]:
    if not token:
        return None
    try:
        payload = parse_token(token, expected_type=TOKEN_TYPE_ACCESS)
        user_id = UUID(str(payload["sub"]))
    except (ValueError, TypeError):
        return None
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        return None
    return user


def require_roles(*allowed_roles: UserRole) -> Callable[..., User]:
    """Dependency factory: require authenticated user with one of the given roles."""

    allowed = set(allowed_roles)

    async def _dependency(
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        if current_user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{current_user.role.value}' is not permitted. "
                    f"Required: {[r.value for r in allowed_roles]}"
                ),
            )
        return current_user

    return _dependency


# Convenience role bundles
RequireAdmin = Annotated[User, Depends(require_roles(UserRole.ADMIN))]
RequirePentesterOrAdmin = Annotated[
    User, Depends(require_roles(UserRole.ADMIN, UserRole.PENTESTER))
]
RequireAnyAuthenticated = Annotated[User, Depends(get_current_user)]
RequireSocOrAbove = Annotated[
    User,
    Depends(require_roles(UserRole.ADMIN, UserRole.PENTESTER, UserRole.SOC_ANALYST)),
]
