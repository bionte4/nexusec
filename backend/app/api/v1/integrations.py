"""Integration control / test endpoints (webhooks, tickets, SIEM)."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select

from app.core.database import get_db
from app.core.deps import RequireAdmin, RequirePentesterOrAdmin, RequireTenant
from app.core.enums import FindingStatus, Severity
from app.integrations import build_finding_event, dispatch_integrations
from app.integrations.siem import to_cef, to_json_syslog
from app.integrations.webhooks import (
    build_generic_payload,
    build_slack_payload,
    build_teams_payload,
    mask_webhook_url,
    resolve_webhook_config,
)
from app.models.organization import Organization
from app.models.vulnerability import Vulnerability

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

router = APIRouter(prefix="/integrations", tags=["integrations"])


class DispatchRequest(BaseModel):
    send_webhook: bool = True
    sync_ticket: bool = True
    forward_siem: bool = True
    async_mode: bool = True


class PreviewFinding(BaseModel):
    title: str = "Sample critical vulnerability"
    severity: Severity = Severity.CRITICAL
    status: FindingStatus = FindingStatus.CONFIRMED
    asset_name: str = "demo-asset"
    cve_id: Optional[str] = "CVE-2024-0001"
    cwe_id: Optional[str] = "CWE-79"
    cvss_score: Optional[float] = 9.8
    description: Optional[str] = "Preview payload for integrations"


class WebhookSettingsUpdate(BaseModel):
    enabled: Optional[bool] = None
    provider: Optional[str] = Field(default=None, pattern="^(generic|slack|teams)$")
    min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    urls: Optional[list[str]] = None


def _org_scope(tenant: RequireTenant) -> uuid.UUID | None:
    return None if tenant.cross_tenant else tenant.organization_id


@router.get("/status", summary="Integration configuration status (no secrets)")
async def integration_status(
    tenant: RequireTenant,
    _: RequireAdmin,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    from app.core.config import get_settings

    s = get_settings()
    org_settings = None
    if tenant.organization_id is not None:
        org = (
            await db.execute(
                select(Organization).where(Organization.id == tenant.organization_id)
            )
        ).scalar_one_or_none()
        if org is not None:
            org_settings = org.settings

    webhook = resolve_webhook_config(org_settings)
    return {
        "webhook": {
            "enabled": webhook["enabled"],
            "provider": webhook["provider"],
            "endpoints_configured": len(webhook["urls"]),
            "urls_masked": [mask_webhook_url(u) for u in webhook["urls"]],
            "min_severity": webhook["min_severity"],
            "source": webhook["source"],
        },
        "ticketing": {
            "enabled": s.ticket_enabled,
            "provider": s.ticket_provider,
            "min_severity": s.ticket_min_severity,
            "jira_configured": bool(s.jira_base_url and s.jira_api_token),
            "servicenow_configured": bool(
                s.servicenow_instance_url and s.servicenow_username
            ),
        },
        "siem": {
            "enabled": s.siem_enabled,
            "format": s.siem_format,
            "collector_configured": bool(s.siem_webhook_url),
        },
    }


@router.get(
    "/webhook-settings",
    summary="Get tenant webhook settings (URLs masked)",
)
async def get_webhook_settings(
    tenant: RequireTenant,
    _: RequireAdmin,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    org_id = tenant.require_organization_id()
    org = (
        await db.execute(select(Organization).where(Organization.id == org_id))
    ).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    webhook = resolve_webhook_config(org.settings)
    return {
        "enabled": webhook["enabled"],
        "provider": webhook["provider"],
        "min_severity": webhook["min_severity"],
        "urls_masked": [mask_webhook_url(u) for u in webhook["urls"]],
        "endpoints_configured": len(webhook["urls"]),
        "source": webhook["source"],
    }


@router.patch(
    "/webhook-settings",
    summary="Update tenant webhook settings (stored in organization.settings)",
)
async def patch_webhook_settings(
    payload: WebhookSettingsUpdate,
    tenant: RequireTenant,
    _: RequireAdmin,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    org_id = tenant.require_organization_id()
    org = (
        await db.execute(select(Organization).where(Organization.id == org_id))
    ).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    settings = dict(org.settings or {})
    integ = dict(settings.get("integrations") or {})
    wh = dict(integ.get("webhook") or {})
    data = payload.model_dump(exclude_unset=True)
    if "urls" in data and data["urls"] is not None:
        cleaned = []
        for u in data["urls"]:
            u = str(u).strip()
            if not u:
                continue
            if not (u.startswith("https://") or u.startswith("http://")):
                raise HTTPException(
                    status_code=400, detail="Webhook URLs must be http(s)"
                )
            cleaned.append(u)
        wh["urls"] = cleaned
        data.pop("urls")
    wh.update(data)
    integ["webhook"] = wh
    settings["integrations"] = integ
    org.settings = settings
    await db.flush()
    await db.refresh(org)

    webhook = resolve_webhook_config(org.settings)
    return {
        "enabled": webhook["enabled"],
        "provider": webhook["provider"],
        "min_severity": webhook["min_severity"],
        "urls_masked": [mask_webhook_url(u) for u in webhook["urls"]],
        "endpoints_configured": len(webhook["urls"]),
        "source": webhook["source"],
    }


@router.post(
    "/preview",
    summary="Preview Slack/Teams/generic/CEF/JSON payloads (no outbound send)",
)
async def preview_payloads(
    payload: PreviewFinding,
    _: RequirePentesterOrAdmin,
) -> dict[str, Any]:
    finding = build_finding_event(
        vulnerability_id=uuid.uuid4(),
        title=payload.title,
        severity=payload.severity,
        status=payload.status,
        asset_id=uuid.uuid4(),
        asset_name=payload.asset_name,
        cve_id=payload.cve_id,
        cwe_id=payload.cwe_id,
        cvss_score=payload.cvss_score,
        description=payload.description,
        source_tool="preview",
    )
    return {
        "finding": finding,
        "slack": build_slack_payload(finding),
        "teams": build_teams_payload(finding),
        "generic": build_generic_payload(finding),
        "siem_json": to_json_syslog(finding),
        "siem_cef": to_cef(finding),
    }


@router.post(
    "/vulnerabilities/{vulnerability_id}/dispatch",
    summary="Dispatch webhook + ticket + SIEM for a vulnerability",
)
async def dispatch_for_vulnerability(
    vulnerability_id: uuid.UUID,
    payload: DispatchRequest,
    _: RequirePentesterOrAdmin,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    stmt = (
        select(Vulnerability)
        .options(selectinload(Vulnerability.asset))
        .where(Vulnerability.id == vulnerability_id)
    )
    vuln = (await db.execute(stmt)).scalar_one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    if payload.async_mode:
        from workers.integration_tasks import dispatch_finding_integrations

        task = dispatch_finding_integrations.delay(
            str(vulnerability_id),
            send_webhook=payload.send_webhook,
            sync_ticket=payload.sync_ticket,
            forward_siem=payload.forward_siem,
        )
        return {"mode": "async", "task_id": task.id, "vulnerability_id": str(vulnerability_id)}

    asset_name = vuln.asset.name if vuln.asset is not None else str(vuln.asset_id)
    event = build_finding_event(
        vulnerability_id=vuln.id,
        title=vuln.title,
        severity=vuln.severity,
        status=vuln.status,
        asset_id=vuln.asset_id,
        asset_name=asset_name,
        cve_id=vuln.cve_id,
        cwe_id=vuln.cwe_id,
        cvss_score=vuln.cvss_score,
        source_tool=vuln.source_tool,
        description=vuln.description,
    )
    result = dispatch_integrations(
        event,
        existing_ticket_key=vuln.external_ticket_key,
        send_webhook=payload.send_webhook,
        sync_ticket=payload.sync_ticket,
        forward_siem=payload.forward_siem,
    )
    ticket = result.get("ticket") or {}
    if ticket.get("key"):
        vuln.external_ticket_system = ticket.get("provider")
        vuln.external_ticket_key = ticket.get("key")
        vuln.external_ticket_url = ticket.get("url")
        await db.flush()
    return {"mode": "sync", **result}


@router.get(
    "/digest/preview",
    summary="Preview SOC digest (overdue + critical/high) without sending",
)
async def preview_digest(
    tenant: RequireTenant,
    _: RequireAdmin,
) -> dict[str, Any]:
    from workers.db import session_scope
    from app.services.digest_service import DigestService

    org_id = None if tenant.cross_tenant else tenant.organization_id
    with session_scope() as session:
        digest = DigestService(session).build_digest(organization_id=org_id)
    return {"digest": digest}


@router.post(
    "/digest/send",
    summary="Send SOC digest now (or enqueue async)",
)
async def send_digest(
    tenant: RequireTenant,
    _: RequireAdmin,
    async_mode: bool = True,
) -> dict[str, Any]:
    if async_mode:
        from workers.integration_tasks import send_soc_digest_task

        task = send_soc_digest_task.delay()
        return {"mode": "async", "task_id": task.id}

    from workers.db import session_scope
    from app.services.digest_service import DigestService

    org_id = None if tenant.cross_tenant else tenant.organization_id
    with session_scope() as session:
        svc = DigestService(session)
        if org_id is not None:
            org = session.get(Organization, org_id)
            digest = svc.build_digest(organization_id=org_id)
            deliveries = svc.send_digest(
                digest, org_settings=org.settings if org else None
            )
            return {
                "mode": "sync",
                "organization_id": str(org_id),
                "digest": digest,
                "deliveries": deliveries,
            }
        return {"mode": "sync", **svc.run_for_all_orgs()}
