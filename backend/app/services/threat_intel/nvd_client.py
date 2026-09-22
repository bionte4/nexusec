"""NVD CVE 2.0 API client — detect public exploit references.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
Optional API key via NVD_API_KEY for higher rate limits.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_EXPLOIT_HOST_HINTS = (
    "exploit-db.com",
    "exploits.",
    "metasploit",
    "packetstormsecurity",
    "github.com/",
    "rapid7.com",
)
_EXPLOIT_TAG_HINTS = ("exploit", "proof of concept", "poc")


@dataclass(frozen=True)
class NvdEnrichment:
    cve_id: str
    cvss_score: Optional[float]
    exploitability_score: Optional[float]
    has_public_exploit: bool
    exploit_references: list[str]
    raw: dict[str, Any]


def _extract_cvss(metrics: dict[str, Any]) -> tuple[Optional[float], Optional[float]]:
    """Prefer CVSS v3.1, then v3.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        primary = items[0]
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        exploitability = primary.get("exploitabilityScore")
        return (
            float(score) if score is not None else None,
            float(exploitability) if exploitability is not None else None,
        )
    return None, None


def detect_public_exploits(cve_item: dict[str, Any]) -> tuple[bool, list[str]]:
    """Heuristic: NVD reference tags / known exploit hostnames."""
    refs: list[str] = []
    cve = cve_item.get("cve") or cve_item
    for ref in cve.get("references") or []:
        url = str(ref.get("url") or "")
        tags = [str(t).lower() for t in (ref.get("tags") or [])]
        url_l = url.lower()
        tag_hit = any(any(h in t for h in _EXPLOIT_TAG_HINTS) for t in tags)
        host_hit = any(h in url_l for h in _EXPLOIT_HOST_HINTS)
        if tag_hit or host_hit:
            refs.append(url)
    return (len(refs) > 0), refs


def parse_nvd_response(payload: dict[str, Any], cve_id: str) -> Optional[NvdEnrichment]:
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    item = vulnerabilities[0]
    cve = item.get("cve") or {}
    metrics = cve.get("metrics") or {}
    cvss, exploitability = _extract_cvss(metrics)
    has_exploit, refs = detect_public_exploits(item)
    return NvdEnrichment(
        cve_id=cve_id.upper(),
        cvss_score=cvss,
        exploitability_score=exploitability,
        has_public_exploit=has_exploit,
        exploit_references=refs,
        raw={"id": cve.get("id"), "references_sample": refs[:10]},
    )


def fetch_nvd_cve(
    cve_id: str,
    *,
    api_key: Optional[str] = None,
    timeout: float = 30.0,
    client: Optional[httpx.Client] = None,
    rate_limit_sleep: float = 0.6,
) -> Optional[NvdEnrichment]:
    """Fetch a single CVE from NVD. Respects public rate limits when no API key."""
    cve_id = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return None

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout, follow_redirects=True)
    headers = {"Accept": "application/json", "User-Agent": "NexuSec/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        if rate_limit_sleep > 0 and not api_key:
            time.sleep(rate_limit_sleep)
        response = http.get(NVD_CVE_API, params={"cveId": cve_id}, headers=headers)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return parse_nvd_response(response.json(), cve_id)
    finally:
        if owns_client:
            http.close()
