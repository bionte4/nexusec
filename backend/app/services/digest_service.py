"""SOC digest — overdue SLA + open Critical/High summary for webhook delivery."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings, get_settings
from app.core.enums import ACTIVE_FINDING_STATUSES, Severity
from app.integrations.webhooks import (
    WebhookNotifier,
    _redact_url,
)
from app.models.organization import Organization
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


def build_digest_slack_payload(digest: dict[str, Any]) -> dict[str, Any]:
    overdue = digest.get("overdue_count", 0)
    crit = digest.get("open_critical", 0)
    high = digest.get("open_high", 0)
    lines = [
        f"*Overdue SLA:* {overdue}",
        f"*Open Critical:* {crit}",
        f"*Open High:* {high}",
        f"*Active findings:* {digest.get('active_total', 0)}",
    ]
    top = digest.get("top_findings") or []
    if top:
        lines.append("*Top items:*")
        for item in top[:8]:
            lines.append(
                f"• `{item.get('severity')}` {item.get('title')} "
                f"({item.get('asset_name')})"
            )
    return {
        "text": (
            f"[NexuSec Digest] overdue={overdue} critical={crit} high={high}"
        ),
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "NexuSec daily digest"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(lines)},
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"org=`{digest.get('organization_id') or 'all'}` · "
                            f"generated=`{digest.get('generated_at')}`"
                        ),
                    }
                ],
            },
        ],
    }


def build_digest_teams_payload(digest: dict[str, Any]) -> dict[str, Any]:
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": "NexuSec digest",
        "themeColor": "0078D4",
        "title": "NexuSec daily digest",
        "sections": [
            {
                "facts": [
                    {"name": "Overdue SLA", "value": str(digest.get("overdue_count", 0))},
                    {"name": "Open Critical", "value": str(digest.get("open_critical", 0))},
                    {"name": "Open High", "value": str(digest.get("open_high", 0))},
                    {"name": "Active total", "value": str(digest.get("active_total", 0))},
                ],
                "text": "\n".join(
                    f"- [{i.get('severity')}] {i.get('title')} @ {i.get('asset_name')}"
                    for i in (digest.get("top_findings") or [])[:8]
                ),
            }
        ],
    }


def build_digest_generic_payload(digest: dict[str, Any]) -> dict[str, Any]:
    return {"event": "nexusec.digest", "digest": digest}


class DigestService:
    """Build and optionally deliver SOC digests (sync Session for Celery)."""

    def __init__(
        self,
        session: Session,
        settings: Optional[Settings] = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()

    def build_digest(
        self,
        *,
        organization_id: Optional[UUID] = None,
        top_n: int = 10,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        filters = [Vulnerability.status.in_(tuple(ACTIVE_FINDING_STATUSES))]
        if organization_id is not None:
            filters.append(Vulnerability.organization_id == organization_id)

        active_total = int(
            self.session.scalar(
                select(func.count()).select_from(Vulnerability).where(*filters)
            )
            or 0
        )
        open_critical = int(
            self.session.scalar(
                select(func.count())
                .select_from(Vulnerability)
                .where(*filters, Vulnerability.severity == Severity.CRITICAL)
            )
            or 0
        )
        open_high = int(
            self.session.scalar(
                select(func.count())
                .select_from(Vulnerability)
                .where(*filters, Vulnerability.severity == Severity.HIGH)
            )
            or 0
        )
        overdue_count = int(
            self.session.scalar(
                select(func.count())
                .select_from(Vulnerability)
                .where(
                    *filters,
                    Vulnerability.remediation_due_at.is_not(None),
                    Vulnerability.remediation_due_at < now,
                )
            )
            or 0
        )

        top_stmt = (
            select(Vulnerability)
            .options(selectinload(Vulnerability.asset))
            .where(*filters)
            .order_by(
                Vulnerability.severity.asc(),
                Vulnerability.threat_risk_score.desc().nullslast(),
                Vulnerability.updated_at.desc(),
            )
            .limit(top_n)
        )
        # Prefer overdue items first in the digest list
        overdue_stmt = (
            select(Vulnerability)
            .options(selectinload(Vulnerability.asset))
            .where(
                *filters,
                Vulnerability.remediation_due_at.is_not(None),
                Vulnerability.remediation_due_at < now,
            )
            .order_by(Vulnerability.remediation_due_at.asc())
            .limit(top_n)
        )
        overdue_rows = list(self.session.scalars(overdue_stmt).all())
        top_rows = overdue_rows or list(self.session.scalars(top_stmt).all())
        if overdue_rows and len(overdue_rows) < top_n:
            seen = {v.id for v in overdue_rows}
            for v in self.session.scalars(top_stmt).all():
                if v.id not in seen:
                    top_rows.append(v)
                if len(top_rows) >= top_n:
                    break

        top_findings = []
        for v in top_rows[:top_n]:
            asset_name = v.asset.name if v.asset is not None else str(v.asset_id)
            top_findings.append(
                {
                    "vulnerability_id": str(v.id),
                    "title": v.title,
                    "severity": v.severity.value
                    if isinstance(v.severity, Severity)
                    else str(v.severity),
                    "status": v.status.value if hasattr(v.status, "value") else str(v.status),
                    "asset_name": asset_name,
                    "remediation_due_at": (
                        v.remediation_due_at.isoformat() if v.remediation_due_at else None
                    ),
                    "threat_risk_score": v.threat_risk_score,
                    "overdue": bool(
                        v.remediation_due_at is not None and v.remediation_due_at < now
                    ),
                }
            )

        return {
            "generated_at": now.isoformat(),
            "organization_id": str(organization_id) if organization_id else None,
            "overdue_count": overdue_count,
            "open_critical": open_critical,
            "open_high": open_high,
            "active_total": active_total,
            "top_findings": top_findings,
        }

    def send_digest(
        self,
        digest: dict[str, Any],
        *,
        org_settings: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        if not self.settings.digest_enabled:
            return [{"skipped": True, "reason": "digest_disabled"}]

        notifier = WebhookNotifier(org_settings=org_settings)
        if not notifier.enabled or not notifier.urls:
            return [{"skipped": True, "reason": "webhook_disabled_or_empty"}]

        if notifier.provider == "slack":
            body = build_digest_slack_payload(digest)
        elif notifier.provider == "teams":
            body = build_digest_teams_payload(digest)
        else:
            body = build_digest_generic_payload(digest)

        results: list[dict[str, Any]] = []
        with httpx.Client(timeout=notifier.timeout_seconds) as client:
            for url in notifier.urls:
                try:
                    resp = client.post(url, json=body)
                    results.append(
                        {
                            "url": _redact_url(url),
                            "status_code": resp.status_code,
                            "ok": 200 <= resp.status_code < 300,
                        }
                    )
                except httpx.HTTPError as exc:
                    logger.warning("Digest webhook error: %s", exc)
                    results.append({"url": _redact_url(url), "ok": False, "error": str(exc)})
        return results

    def run_for_all_orgs(self) -> dict[str, Any]:
        """Send one digest per organization (and env-level webhook)."""
        orgs = list(self.session.scalars(select(Organization)).all())
        outcomes: list[dict[str, Any]] = []
        if not orgs:
            digest = self.build_digest()
            deliveries = self.send_digest(digest)
            return {
                "ok": True,
                "organizations": 0,
                "digest": digest,
                "deliveries": deliveries,
            }

        for org in orgs:
            digest = self.build_digest(organization_id=org.id)
            # Skip quiet digests unless configured to always send
            if (
                not self.settings.digest_send_when_empty
                and digest["overdue_count"] == 0
                and digest["open_critical"] == 0
                and digest["open_high"] == 0
            ):
                outcomes.append(
                    {
                        "organization_id": str(org.id),
                        "skipped": True,
                        "reason": "empty_digest",
                    }
                )
                continue
            deliveries = self.send_digest(digest, org_settings=org.settings)
            outcomes.append(
                {
                    "organization_id": str(org.id),
                    "digest": {
                        "overdue_count": digest["overdue_count"],
                        "open_critical": digest["open_critical"],
                        "open_high": digest["open_high"],
                    },
                    "deliveries": deliveries,
                }
            )
        return {"ok": True, "organizations": len(orgs), "outcomes": outcomes}
