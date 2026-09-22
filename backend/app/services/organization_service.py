"""Organization / tenant management service."""

from __future__ import annotations

import math
import re
import secrets
import uuid
from typing import Any, Optional

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ACTIVE_FINDING_STATUSES, Severity
from app.core.security import hash_password, verify_password
from app.models.asset import Asset
from app.models.organization import Organization
from app.models.scan import Scan
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationListResponse,
    OrganizationMetrics,
    OrganizationRead,
    OrganizationUpdate,
    WorkspaceTokenResponse,
)


class OrganizationNotFoundError(Exception):
    pass


class OrganizationValidationError(Exception):
    pass


_SLUG_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{1,62}[a-z0-9])?$")


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:64] or "org"


def _generate_workspace_token() -> tuple[str, str, str]:
    """Return (plaintext, hash, prefix)."""
    raw = f"nxa_{secrets.token_urlsafe(32)}"
    prefix = raw[:12]
    return raw, hash_password(raw), prefix


def _to_read(org: Organization, *, workspace_token: Optional[str] = None) -> OrganizationRead:
    data = OrganizationRead.model_validate(org)
    if workspace_token:
        return data.model_copy(update={"workspace_token": workspace_token})
    return data


class OrganizationService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(self, payload: OrganizationCreate) -> OrganizationRead:
        slug = (payload.slug or _slugify(payload.name)).lower()
        if not _SLUG_RE.match(slug):
            raise OrganizationValidationError(
                "slug must be 3–64 chars: lowercase alphanumeric and hyphens"
            )
        existing = await self.db.scalar(select(Organization).where(Organization.slug == slug))
        if existing is not None:
            raise OrganizationValidationError(f"slug '{slug}' already exists")

        token, token_hash, prefix = _generate_workspace_token()
        org = Organization(
            name=payload.name.strip(),
            slug=slug,
            description=payload.description,
            is_active=True,
            workspace_token_hash=token_hash,
            workspace_token_prefix=prefix,
            settings=payload.settings or {},
        )
        self.db.add(org)
        await self.db.flush()
        await self.db.refresh(org)
        return _to_read(org, workspace_token=token)

    async def list(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> OrganizationListResponse:
        page = max(page, 1)
        page_size = min(max(page_size, 1), 100)
        filters: list[Any] = []
        if search:
            pattern = f"%{search.strip()}%"
            filters.append(or_(Organization.name.ilike(pattern), Organization.slug.ilike(pattern)))
        if is_active is not None:
            filters.append(Organization.is_active.is_(is_active))

        count_stmt = select(func.count()).select_from(Organization)
        if filters:
            count_stmt = count_stmt.where(*filters)
        total = int(await self.db.scalar(count_stmt) or 0)

        stmt: Select[tuple[Organization]] = (
            select(Organization)
            .order_by(Organization.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        if filters:
            stmt = stmt.where(*filters)
        rows = list((await self.db.scalars(stmt)).all())
        pages = math.ceil(total / page_size) if total else 0
        return OrganizationListResponse(
            items=[_to_read(o) for o in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
        )

    async def get(self, organization_id: uuid.UUID) -> OrganizationRead:
        org = await self._get_or_raise(organization_id)
        return _to_read(org)

    async def update(
        self, organization_id: uuid.UUID, payload: OrganizationUpdate
    ) -> OrganizationRead:
        org = await self._get_or_raise(organization_id)
        data = payload.model_dump(exclude_unset=True)
        for field, value in data.items():
            setattr(org, field, value)
        await self.db.flush()
        await self.db.refresh(org)
        return _to_read(org)

    async def rotate_workspace_token(self, organization_id: uuid.UUID) -> WorkspaceTokenResponse:
        org = await self._get_or_raise(organization_id)
        token, token_hash, prefix = _generate_workspace_token()
        org.workspace_token_hash = token_hash
        org.workspace_token_prefix = prefix
        await self.db.flush()
        return WorkspaceTokenResponse(
            organization_id=org.id,
            workspace_token=token,
            workspace_token_prefix=prefix,
        )

    async def verify_workspace_token(self, token: str) -> Optional[Organization]:
        prefix = token[:12] if len(token) >= 12 else token
        stmt = select(Organization).where(
            Organization.workspace_token_prefix == prefix,
            Organization.is_active.is_(True),
        )
        candidates = list((await self.db.scalars(stmt)).all())
        for org in candidates:
            if org.workspace_token_hash and verify_password(token, org.workspace_token_hash):
                return org
        return None

    async def metrics(self, organization_id: uuid.UUID) -> OrganizationMetrics:
        await self._get_or_raise(organization_id)
        asset_count = int(
            await self.db.scalar(
                select(func.count())
                .select_from(Asset)
                .where(Asset.organization_id == organization_id)
            )
            or 0
        )
        scan_count = int(
            await self.db.scalar(
                select(func.count())
                .select_from(Scan)
                .where(Scan.organization_id == organization_id)
            )
            or 0
        )
        user_count = int(
            await self.db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.organization_id == organization_id)
            )
            or 0
        )
        open_vulns = int(
            await self.db.scalar(
                select(func.count())
                .select_from(Vulnerability)
                .where(
                    Vulnerability.organization_id == organization_id,
                    Vulnerability.status.in_(list(ACTIVE_FINDING_STATUSES)),
                )
            )
            or 0
        )
        critical_open = int(
            await self.db.scalar(
                select(func.count())
                .select_from(Vulnerability)
                .where(
                    Vulnerability.organization_id == organization_id,
                    Vulnerability.status.in_(list(ACTIVE_FINDING_STATUSES)),
                    Vulnerability.severity == Severity.CRITICAL,
                )
            )
            or 0
        )
        actively_exploited = int(
            await self.db.scalar(
                select(func.count())
                .select_from(Vulnerability)
                .where(
                    Vulnerability.organization_id == organization_id,
                    Vulnerability.is_actively_exploited.is_(True),
                    Vulnerability.status.in_(list(ACTIVE_FINDING_STATUSES)),
                )
            )
            or 0
        )
        cde_assets = int(
            await self.db.scalar(
                select(func.count())
                .select_from(Asset)
                .where(
                    Asset.organization_id == organization_id,
                    Asset.is_cde_scope.is_(True),
                )
            )
            or 0
        )
        return OrganizationMetrics(
            organization_id=organization_id,
            users=user_count,
            assets=asset_count,
            scans=scan_count,
            open_vulnerabilities=open_vulns,
            critical_open=critical_open,
            actively_exploited=actively_exploited,
            cde_assets=cde_assets,
        )

    async def _get_or_raise(self, organization_id: uuid.UUID) -> Organization:
        org = await self.db.get(Organization, organization_id)
        if org is None:
            raise OrganizationNotFoundError(f"Organization {organization_id} not found")
        return org
