"""Webhook alerts for Slack, Microsoft Teams, and generic receivers."""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from app.core.config import get_settings
from app.core.enums import Severity
from app.integrations.common import finding_payload, severity_rank

logger = logging.getLogger(__name__)


class WebhookDeliveryError(Exception):
    pass


def build_slack_payload(finding: dict[str, Any]) -> dict[str, Any]:
    sev = finding.get("severity", "unknown").upper()
    return {
        "text": f"[NexuSec] {sev}: {finding.get('title')}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"NexuSec Alert — {sev}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Title*\n{finding.get('title')}"},
                    {"type": "mrkdwn", "text": f"*Asset*\n{finding.get('asset_name')}"},
                    {"type": "mrkdwn", "text": f"*Severity*\n{sev}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*CVE*\n{finding.get('cve_id') or 'n/a'}",
                    },
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"vuln_id=`{finding.get('vulnerability_id')}` · "
                            f"status=`{finding.get('status')}`"
                        ),
                    }
                ],
            },
        ],
    }


def build_teams_payload(finding: dict[str, Any]) -> dict[str, Any]:
    sev = finding.get("severity", "unknown").upper()
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"NexuSec {sev} alert",
        "themeColor": "FF0000" if sev == "CRITICAL" else "FFA500",
        "title": f"NexuSec Alert — {sev}",
        "sections": [
            {
                "facts": [
                    {"name": "Title", "value": finding.get("title")},
                    {"name": "Asset", "value": finding.get("asset_name")},
                    {"name": "Severity", "value": sev},
                    {"name": "CVE", "value": finding.get("cve_id") or "n/a"},
                    {"name": "Vulnerability ID", "value": finding.get("vulnerability_id")},
                ],
                "text": finding.get("description") or "",
            }
        ],
    }


def build_generic_payload(finding: dict[str, Any]) -> dict[str, Any]:
    return {"event": "vulnerability.alert", "finding": finding}


def mask_webhook_url(url: str) -> str:
    raw = (url or "").strip()
    if len(raw) < 16:
        return "***"
    # Keep scheme + host, mask the rest
    try:
        from urllib.parse import urlparse

        parsed = urlparse(raw)
        host = parsed.netloc or "****"
        return f"{parsed.scheme}://{host}/***"
    except Exception:
        return raw[:12] + "***"


def resolve_webhook_config(org_settings: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Merge org.settings.integrations.webhook over env defaults."""
    settings = get_settings()
    cfg: dict[str, Any] = {
        "enabled": settings.webhook_enabled,
        "provider": settings.webhook_provider,
        "min_severity": settings.webhook_min_severity,
        "urls": list(settings.webhook_url_list),
        "source": "env",
    }
    if not org_settings:
        return cfg
    integ = org_settings.get("integrations") if isinstance(org_settings, dict) else None
    wh = integ.get("webhook") if isinstance(integ, dict) else None
    if not isinstance(wh, dict):
        return cfg
    if "enabled" in wh:
        cfg["enabled"] = bool(wh["enabled"])
    if wh.get("provider"):
        cfg["provider"] = str(wh["provider"]).lower()
    if wh.get("min_severity"):
        cfg["min_severity"] = str(wh["min_severity"]).lower()
    if isinstance(wh.get("urls"), list) and wh["urls"]:
        cfg["urls"] = [str(u).strip() for u in wh["urls"] if str(u).strip()]
        cfg["source"] = "organization"
    elif any(k in wh for k in ("enabled", "provider", "min_severity")):
        cfg["source"] = "organization+env"
    return cfg


class WebhookNotifier:
    """POST finding alerts to configured webhook URLs."""

    def __init__(
        self,
        *,
        urls: Optional[list[str]] = None,
        provider: Optional[str] = None,
        min_severity: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout_seconds: float = 10.0,
        org_settings: Optional[dict[str, Any]] = None,
    ) -> None:
        resolved = resolve_webhook_config(org_settings)
        self.urls = urls if urls is not None else list(resolved["urls"])
        self.provider = (provider or resolved["provider"]).lower()
        self.min_severity = (min_severity or resolved["min_severity"]).lower()
        self.enabled = resolved["enabled"] if enabled is None else enabled
        self.timeout_seconds = timeout_seconds

    def should_alert(self, severity: Severity | str) -> bool:
        if not self.enabled or not self.urls:
            return False
        return severity_rank(severity) >= severity_rank(self.min_severity)

    def build_body(self, finding: dict[str, Any]) -> dict[str, Any]:
        if self.provider == "slack":
            return build_slack_payload(finding)
        if self.provider == "teams":
            return build_teams_payload(finding)
        return build_generic_payload(finding)

    def send(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.should_alert(finding.get("severity", "info")):
            return [{"skipped": True, "reason": "below_threshold_or_disabled"}]

        body = self.build_body(finding)
        results: list[dict[str, Any]] = []
        with httpx.Client(timeout=self.timeout_seconds) as client:
            for url in self.urls:
                try:
                    resp = client.post(url, json=body)
                    results.append(
                        {
                            "url": _redact_url(url),
                            "status_code": resp.status_code,
                            "ok": 200 <= resp.status_code < 300,
                        }
                    )
                    if not (200 <= resp.status_code < 300):
                        logger.warning(
                            "Webhook delivery failed status=%s url=%s",
                            resp.status_code,
                            _redact_url(url),
                        )
                except httpx.HTTPError as exc:
                    logger.warning("Webhook delivery error url=%s err=%s", _redact_url(url), exc)
                    results.append({"url": _redact_url(url), "ok": False, "error": str(exc)})
        return results


def _redact_url(url: str) -> str:
    # Avoid logging tokens embedded in query strings
    if "?" in url:
        return url.split("?", 1)[0] + "?…"
    return url


def alert_from_fields(**kwargs: Any) -> list[dict[str, Any]]:
    return WebhookNotifier().send(finding_payload(**kwargs))
