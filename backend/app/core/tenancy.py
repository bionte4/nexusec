"""Tenant scope helpers — organization isolation for multi-tenancy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import ColumnElement

from app.core.enums import UserRole
from app.models.user import User


@dataclass(frozen=True)
class TenantContext:
    """Resolved tenant scope for the current request."""

    user: User
    organization_id: Optional[UUID]
    """Scoped org id. None when Super Admin is in cross-tenant mode."""

    is_super_admin: bool
    cross_tenant: bool
    """True when Super Admin views all tenants (no X-Organization-Id)."""

    def require_organization_id(self) -> UUID:
        if self.organization_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Organization scope required. Pass X-Organization-Id "
                    "(Super Admin) or ensure the user belongs to an organization."
                ),
            )
        return self.organization_id

    def can_access_org(self, organization_id: UUID) -> bool:
        if self.is_super_admin:
            return True
        return self.organization_id == organization_id


def is_super_admin(user: User) -> bool:
    return user.role == UserRole.SUPER_ADMIN


def org_filter(column: ColumnElement, tenant: TenantContext) -> Optional[ColumnElement]:
    """Equality filter for organization_id, or None for cross-tenant Super Admin."""
    if tenant.cross_tenant or tenant.organization_id is None:
        return None
    return column == tenant.organization_id


def resolve_tenant_context(
    user: User,
    *,
    x_organization_id: Optional[str] = None,
) -> TenantContext:
    """
    Resolve tenant scope from the authenticated user + optional header.

    - Normal users: locked to ``user.organization_id``.
    - Super Admin: ``X-Organization-Id`` scopes to one tenant; omit for cross-tenant reads.
    """
    super_admin = is_super_admin(user)

    header_org: Optional[UUID] = None
    if x_organization_id:
        try:
            header_org = UUID(x_organization_id.strip())
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid X-Organization-Id",
            ) from exc

    if super_admin:
        if header_org is not None:
            return TenantContext(
                user=user,
                organization_id=header_org,
                is_super_admin=True,
                cross_tenant=False,
            )
        return TenantContext(
            user=user,
            organization_id=None,
            is_super_admin=True,
            cross_tenant=True,
        )

    if user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not assigned to an organization",
        )
    if header_org is not None and header_org != user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot access another organization's data",
        )
    return TenantContext(
        user=user,
        organization_id=user.organization_id,
        is_super_admin=False,
        cross_tenant=False,
    )
