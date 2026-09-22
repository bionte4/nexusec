"""Multi-tenancy and organization scope tests."""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from app.core.enums import UserRole
from app.core.tenancy import resolve_tenant_context
from app.models.user import User
from app.core.security import hash_password
from datetime import datetime, timezone


def _user(*, role: UserRole, org_id: uuid.UUID | None) -> User:
    return User(
        id=uuid.uuid4(),
        email=f"{role.value}-{uuid.uuid4().hex[:6]}@example.com",
        full_name="T",
        hashed_password=hash_password("SecurePass123!"),
        role=role,
        organization_id=org_id,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def test_tenant_user_locked_to_org() -> None:
    org = uuid.uuid4()
    user = _user(role=UserRole.SOC_ANALYST, org_id=org)
    ctx = resolve_tenant_context(user)
    assert ctx.organization_id == org
    assert ctx.cross_tenant is False


def test_tenant_user_cannot_spoof_header() -> None:
    org = uuid.uuid4()
    user = _user(role=UserRole.ADMIN, org_id=org)
    with pytest.raises(HTTPException) as exc:
        resolve_tenant_context(user, x_organization_id=str(uuid.uuid4()))
    assert exc.value.status_code == 403


def test_super_admin_cross_tenant_without_header() -> None:
    user = _user(role=UserRole.SUPER_ADMIN, org_id=None)
    ctx = resolve_tenant_context(user)
    assert ctx.cross_tenant is True
    assert ctx.organization_id is None


def test_super_admin_scoped_with_header() -> None:
    org = uuid.uuid4()
    user = _user(role=UserRole.SUPER_ADMIN, org_id=None)
    ctx = resolve_tenant_context(user, x_organization_id=str(org))
    assert ctx.cross_tenant is False
    assert ctx.organization_id == org
    assert ctx.require_organization_id() == org


def test_user_without_org_forbidden() -> None:
    user = _user(role=UserRole.PENTESTER, org_id=None)
    with pytest.raises(HTTPException) as exc:
        resolve_tenant_context(user)
    assert exc.value.status_code == 403
