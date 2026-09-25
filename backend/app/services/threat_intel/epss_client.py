"""FIRST.org EPSS API client — exploit prediction scoring.

API: https://api.first.org/data/v1/epss
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss"


@dataclass(frozen=True)
class EpssScore:
    cve_id: str
    epss: float
    percentile: float
    score_date: Optional[date] = None


def parse_epss_payload(payload: dict[str, Any]) -> list[EpssScore]:
    rows: list[EpssScore] = []
    for item in payload.get("data") or []:
        cve = str(item.get("cve") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        try:
            epss = float(item.get("epss"))
            percentile = float(item.get("percentile"))
        except (TypeError, ValueError):
            continue
        score_date: Optional[date] = None
        raw_date = item.get("date")
        if raw_date:
            try:
                score_date = date.fromisoformat(str(raw_date)[:10])
            except ValueError:
                score_date = None
        rows.append(
            EpssScore(
                cve_id=cve,
                epss=max(0.0, min(1.0, epss)),
                percentile=max(0.0, min(1.0, percentile)),
                score_date=score_date,
            )
        )
    return rows


def fetch_epss_scores(
    cve_ids: list[str],
    *,
    url: str = DEFAULT_EPSS_URL,
    timeout: float = 20.0,
) -> dict[str, EpssScore]:
    """Fetch EPSS scores for one or more CVEs (batched query)."""
    cleaned: list[str] = []
    for raw in cve_ids:
        cve = (raw or "").strip().upper()
        if cve.startswith("CVE-") and cve not in cleaned:
            cleaned.append(cve)
    if not cleaned:
        return {}

    # FIRST API accepts comma-separated cve query (cap batch size)
    out: dict[str, EpssScore] = {}
    batch_size = 50
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        for i in range(0, len(cleaned), batch_size):
            batch = cleaned[i : i + batch_size]
            try:
                resp = client.get(url, params={"cve": ",".join(batch)})
                resp.raise_for_status()
                payload = resp.json()
            except Exception:
                logger.exception("EPSS fetch failed for batch starting %s", batch[0])
                continue
            for score in parse_epss_payload(payload if isinstance(payload, dict) else {}):
                out[score.cve_id] = score
    return out


def fetch_epss_score(
    cve_id: str,
    *,
    url: str = DEFAULT_EPSS_URL,
    timeout: float = 20.0,
) -> Optional[EpssScore]:
    return fetch_epss_scores([cve_id], url=url, timeout=timeout).get(cve_id.strip().upper())
