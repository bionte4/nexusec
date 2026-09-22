"""CISA KEV catalog client.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: Optional[date]
    due_date: Optional[date]
    known_ransomware_use: str
    required_action: str
    notes: str
    raw: dict[str, Any]


def _parse_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def parse_kev_catalog(payload: dict[str, Any]) -> list[KevEntry]:
    """Parse CISA KEV JSON document into typed entries."""
    vulnerabilities = payload.get("vulnerabilities") or []
    entries: list[KevEntry] = []
    for item in vulnerabilities:
        cve_id = (item.get("cveID") or item.get("cve_id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        entries.append(
            KevEntry(
                cve_id=cve_id,
                vendor_project=str(item.get("vendorProject") or ""),
                product=str(item.get("product") or ""),
                vulnerability_name=str(item.get("vulnerabilityName") or ""),
                date_added=_parse_date(item.get("dateAdded")),
                due_date=_parse_date(item.get("dueDate")),
                known_ransomware_use=str(item.get("knownRansomwareCampaignUse") or "Unknown"),
                required_action=str(item.get("requiredAction") or ""),
                notes=str(item.get("notes") or ""),
                raw=dict(item),
            )
        )
    return entries


def fetch_kev_catalog(
    *,
    url: str = DEFAULT_KEV_URL,
    timeout: float = 60.0,
    client: Optional[httpx.Client] = None,
) -> tuple[list[KevEntry], dict[str, Any]]:
    """
    Download the full CISA KEV catalog.

    Returns (entries, catalog_meta) where catalog_meta includes catalogVersion / dateReleased.
    """
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        response = http.get(
            url, headers={"Accept": "application/json", "User-Agent": "NexuSec/1.0"}
        )
        response.raise_for_status()
        payload = response.json()
        entries = parse_kev_catalog(payload)
        meta = {
            "catalog_version": payload.get("catalogVersion"),
            "date_released": payload.get("dateReleased"),
            "count": len(entries),
            "fetched_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_url": url,
        }
        logger.info("Fetched CISA KEV catalog: %s entries", len(entries))
        return entries, meta
    finally:
        if owns_client:
            http.close()
