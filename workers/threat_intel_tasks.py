"""Celery tasks for CISA KEV / NVD threat intelligence sync."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workers.celery_app import celery_app  # noqa: E402
from workers.db import session_scope  # noqa: E402

logger = logging.getLogger(__name__)


@celery_app.task(name="threat_intel.sync_kev", bind=True, max_retries=2)
def sync_kev_catalog_task(self) -> dict[str, Any]:
    from app.services.threat_intel import ThreatIntelService

    with session_scope() as session:
        return ThreatIntelService(session).sync_kev_catalog()


@celery_app.task(name="threat_intel.enrich_vulnerabilities", bind=True, max_retries=1)
def enrich_vulnerabilities_task(
    self,
    limit: int = 500,
    fetch_nvd: bool = True,
    only_unenriched: bool = False,
) -> dict[str, Any]:
    from app.services.threat_intel import ThreatIntelService

    with session_scope() as session:
        return ThreatIntelService(session).enrich_vulnerabilities(
            limit=limit,
            fetch_nvd=fetch_nvd,
            only_unenriched=only_unenriched,
        )


@celery_app.task(name="threat_intel.full_sync")
def full_threat_intel_sync_task() -> dict[str, Any]:
    """Periodic beat entrypoint: refresh KEV then enrich findings."""
    kev = sync_kev_catalog_task()
    enrich = enrich_vulnerabilities_task(limit=1000, fetch_nvd=True, only_unenriched=False)
    return {"kev": kev, "enrich": enrich}
