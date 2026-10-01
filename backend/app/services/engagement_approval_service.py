"""Dual-control: lead/admin approve engagement scope for client delivery."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import UserRole
from app.models.engagement_approval import EngagementApproval
from app.models.user import User
from app.services.audit_service import AuditService


class EngagementApprovalError(Exception):
    """Raised when approval cannot be granted or is missing for client delivery."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class EngagementApprovalService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def approve(
        self,
        actor: User,
        *,
        organization_id: uuid.UUID,
        scan_id: Optional[uuid.UUID] = None,
        asset_id: Optional[uuid.UUID] = None,
        engagement_type: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> dict[str, Any]:
        if actor.role not in {UserRole.ADMIN, UserRole.SUPER_ADMIN}:
            raise EngagementApprovalError(
                "Only admin or super_admin may approve client engagement delivery "
                "(dual control)."
            )
        # Revoke prior active approvals for the same scope fingerprint
        existing = await self.find_active(
            organization_id=organization_id,
            scan_id=scan_id,
            asset_id=asset_id,
            engagement_type=engagement_type,
        )
        now = datetime.now(timezone.utc)
        if existing is not None:
            existing.revoked_at = now
            existing.revoked_by_id = actor.id
            self.db.add(existing)

        row = EngagementApproval(
            organization_id=organization_id,
            scan_id=scan_id,
            asset_id=asset_id,
            engagement_type=engagement_type,
            notes=(notes or "").strip() or None,
            approved_by_id=actor.id,
            approved_at=now,
        )
        self.db.add(row)
        await self.db.flush()
        await AuditService(self.db).record(
            action="report.engagement.approve",
            resource_type="engagement_approval",
            resource_id=str(row.id),
            actor_id=actor.id,
            organization_id=organization_id,
            details={
                "scan_id": str(scan_id) if scan_id else None,
                "asset_id": str(asset_id) if asset_id else None,
                "engagement_type": engagement_type,
            },
            status_code=200,
        )
        return self._to_dict(row)

    async def revoke(
        self,
        actor: User,
        *,
        organization_id: uuid.UUID,
        scan_id: Optional[uuid.UUID] = None,
        asset_id: Optional[uuid.UUID] = None,
        engagement_type: Optional[str] = None,
    ) -> dict[str, Any]:
        if actor.role not in {UserRole.ADMIN, UserRole.SUPER_ADMIN}:
            raise EngagementApprovalError(
                "Only admin or super_admin may revoke engagement approval."
            )
        row = await self.find_active(
            organization_id=organization_id,
            scan_id=scan_id,
            asset_id=asset_id,
            engagement_type=engagement_type,
        )
        if row is None:
            raise EngagementApprovalError("No active engagement approval for this scope.")
        row.revoked_at = datetime.now(timezone.utc)
        row.revoked_by_id = actor.id
        self.db.add(row)
        await self.db.flush()
        await AuditService(self.db).record(
            action="report.engagement.revoke_approval",
            resource_type="engagement_approval",
            resource_id=str(row.id),
            actor_id=actor.id,
            organization_id=organization_id,
            details={
                "scan_id": str(scan_id) if scan_id else None,
                "asset_id": str(asset_id) if asset_id else None,
                "engagement_type": engagement_type,
            },
            status_code=200,
        )
        return self._to_dict(row)

    async def find_active(
        self,
        *,
        organization_id: uuid.UUID,
        scan_id: Optional[uuid.UUID] = None,
        asset_id: Optional[uuid.UUID] = None,
        engagement_type: Optional[str] = None,
    ) -> Optional[EngagementApproval]:
        stmt = select(EngagementApproval).where(
            EngagementApproval.organization_id == organization_id,
            EngagementApproval.revoked_at.is_(None),
        )
        if scan_id is not None:
            stmt = stmt.where(EngagementApproval.scan_id == scan_id)
        else:
            stmt = stmt.where(EngagementApproval.scan_id.is_(None))
        if asset_id is not None:
            stmt = stmt.where(EngagementApproval.asset_id == asset_id)
        else:
            stmt = stmt.where(EngagementApproval.asset_id.is_(None))
        if engagement_type:
            stmt = stmt.where(EngagementApproval.engagement_type == engagement_type)
        else:
            stmt = stmt.where(EngagementApproval.engagement_type.is_(None))
        stmt = stmt.order_by(EngagementApproval.approved_at.desc()).limit(1)
        return (await self.db.execute(stmt)).scalar_one_or_none()

    async def status(
        self,
        *,
        organization_id: uuid.UUID,
        scan_id: Optional[uuid.UUID] = None,
        asset_id: Optional[uuid.UUID] = None,
        engagement_type: Optional[str] = None,
    ) -> dict[str, Any]:
        row = await self.find_active(
            organization_id=organization_id,
            scan_id=scan_id,
            asset_id=asset_id,
            engagement_type=engagement_type,
        )
        if row is None:
            return {
                "approved": False,
                "approval": None,
                "message": (
                    "No lead/admin approval for this scope. "
                    "Export delivery=draft for internal use, or request approval "
                    "before client delivery."
                ),
            }
        return {
            "approved": True,
            "approval": self._to_dict(row),
            "message": "Scope approved for client engagement delivery.",
        }

    def assert_client_delivery_allowed(
        self,
        approval: Optional[EngagementApproval],
        *,
        delivery: str,
    ) -> None:
        if delivery != "client":
            return
        if approval is None or approval.revoked_at is not None:
            raise EngagementApprovalError(
                "Client engagement delivery requires dual-control approval by "
                "admin/lead. POST /api/v1/reports/engagement/approve for this "
                "scope, or use delivery=draft for internal drafts."
            )

    @staticmethod
    def _to_dict(row: EngagementApproval) -> dict[str, Any]:
        return {
            "id": str(row.id),
            "organization_id": str(row.organization_id),
            "scan_id": str(row.scan_id) if row.scan_id else None,
            "asset_id": str(row.asset_id) if row.asset_id else None,
            "engagement_type": row.engagement_type,
            "notes": row.notes,
            "approved_by_id": str(row.approved_by_id),
            "approved_at": row.approved_at.isoformat() if row.approved_at else None,
            "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        }
