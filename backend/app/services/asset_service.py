"""Business logic for asset inventory management."""

from __future__ import annotations

import math
import uuid
from typing import Any, Optional

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AssetCriticality, AssetType
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetListResponse, AssetRead, AssetUpdate


class AssetNotFoundError(Exception):
    """Raised when an asset UUID does not exist."""


def _to_read(asset: Asset) -> AssetRead:
    return AssetRead.model_validate(asset)


class AssetService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(
        self,
        payload: AssetCreate,
        *,
        organization_id: uuid.UUID,
        created_by_id: Optional[uuid.UUID] = None,
    ) -> AssetRead:
        asset = Asset(
            organization_id=organization_id,
            name=payload.name,
            asset_type=payload.asset_type,
            criticality=payload.criticality,
            ip_address=payload.ip_address,
            domain=payload.domain,
            cloud_resource_id=payload.cloud_resource_id,
            cloud_provider=payload.cloud_provider,
            is_cde_scope=payload.is_cde_scope,
            hostname=payload.hostname,
            url=payload.url,
            environment=payload.environment,
            owner=payload.owner,
            description=payload.description,
            tags=payload.tags,
            metadata_=payload.metadata,
            created_by_id=created_by_id,
        )
        self.db.add(asset)
        await self.db.flush()
        await self.db.refresh(asset)
        return _to_read(asset)

    async def get(
        self, asset_id: uuid.UUID, *, organization_id: Optional[uuid.UUID] = None
    ) -> AssetRead:
        asset = await self._get_or_raise(asset_id, organization_id=organization_id)
        return _to_read(asset)

    async def list(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        search: Optional[str] = None,
        asset_type: Optional[AssetType] = None,
        criticality: Optional[AssetCriticality] = None,
        environment: Optional[str] = None,
        is_cde_scope: Optional[bool] = None,
        organization_id: Optional[uuid.UUID] = None,
    ) -> AssetListResponse:
        page = max(page, 1)
        page_size = min(max(page_size, 1), 100)

        filters = self._build_filters(
            search=search,
            asset_type=asset_type,
            criticality=criticality,
            environment=environment,
            is_cde_scope=is_cde_scope,
            organization_id=organization_id,
        )

        count_stmt = select(func.count()).select_from(Asset)
        if filters:
            count_stmt = count_stmt.where(*filters)
        total = int(await self.db.scalar(count_stmt) or 0)

        stmt: Select[tuple[Asset]] = (
            select(Asset)
            .order_by(Asset.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        if filters:
            stmt = stmt.where(*filters)

        result = await self.db.execute(stmt)
        items = [_to_read(row) for row in result.scalars().all()]
        pages = math.ceil(total / page_size) if total else 0

        return AssetListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
        )

    async def update(
        self,
        asset_id: uuid.UUID,
        payload: AssetUpdate,
        *,
        organization_id: Optional[uuid.UUID] = None,
    ) -> AssetRead:
        asset = await self._get_or_raise(asset_id, organization_id=organization_id)
        data = payload.model_dump(exclude_unset=True)

        if "metadata" in data:
            asset.metadata_ = data.pop("metadata")

        for field, value in data.items():
            setattr(asset, field, value)

        await self.db.flush()
        await self.db.refresh(asset)
        return _to_read(asset)

    async def delete(
        self, asset_id: uuid.UUID, *, organization_id: Optional[uuid.UUID] = None
    ) -> None:
        asset = await self._get_or_raise(asset_id, organization_id=organization_id)
        await self.db.delete(asset)
        await self.db.flush()

    async def _get_or_raise(
        self,
        asset_id: uuid.UUID,
        *,
        organization_id: Optional[uuid.UUID] = None,
    ) -> Asset:
        asset = await self.db.get(Asset, asset_id)
        if asset is None:
            raise AssetNotFoundError(f"Asset {asset_id} not found")
        if organization_id is not None and asset.organization_id != organization_id:
            raise AssetNotFoundError(f"Asset {asset_id} not found")
        return asset

    @staticmethod
    def _build_filters(
        *,
        search: Optional[str],
        asset_type: Optional[AssetType],
        criticality: Optional[AssetCriticality],
        environment: Optional[str],
        is_cde_scope: Optional[bool],
        organization_id: Optional[uuid.UUID] = None,
    ) -> list[Any]:
        filters: list[Any] = []

        if organization_id is not None:
            filters.append(Asset.organization_id == organization_id)

        if search:
            pattern = f"%{search.strip()}%"
            filters.append(
                or_(
                    Asset.name.ilike(pattern),
                    Asset.hostname.ilike(pattern),
                    Asset.domain.ilike(pattern),
                    Asset.cloud_resource_id.ilike(pattern),
                    Asset.url.ilike(pattern),
                    Asset.owner.ilike(pattern),
                    Asset.description.ilike(pattern),
                )
            )

        if asset_type is not None:
            filters.append(Asset.asset_type == asset_type)

        if criticality is not None:
            filters.append(Asset.criticality == criticality)

        if environment:
            filters.append(Asset.environment == environment)

        if is_cde_scope is not None:
            filters.append(Asset.is_cde_scope.is_(is_cde_scope))

        return filters
