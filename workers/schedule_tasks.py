"""Celery Beat dispatcher for due scan schedules."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import selectinload

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workers.celery_app import celery_app  # noqa: E402
from workers.db import session_scope  # noqa: E402

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _enqueue_scan(scan_id: str, engine: str) -> str:
    if engine == "nmap":
        from workers.tasks import run_nmap_scan

        return run_nmap_scan.delay(scan_id).id
    if engine == "nexusec":
        from workers.tasks import run_nexusec_scan

        return run_nexusec_scan.delay(scan_id).id
    if engine == "nuclei":
        from workers.tasks import run_nuclei_scan

        return run_nuclei_scan.delay(scan_id).id
    raise ValueError(f"Unsupported engine for schedule dispatch: {engine}")


@celery_app.task(name="schedules.dispatch_due", bind=True, max_retries=0)
def dispatch_due_schedules(self) -> dict[str, Any]:
    """Create and enqueue scans for every enabled schedule that is due."""
    from app.core.enums import ScanStatus, ScannerEngine
    from app.models.scan import Scan, ScanAsset
    from app.models.scan_schedule import ScanSchedule

    now = _utcnow()
    dispatched = 0
    skipped = 0
    errors = 0

    with session_scope() as session:
        due = (
            session.query(ScanSchedule)
            .options(selectinload(ScanSchedule.assets), selectinload(ScanSchedule.last_scan))
            .filter(
                ScanSchedule.enabled.is_(True),
                ScanSchedule.next_run_at <= now,
            )
            .order_by(ScanSchedule.next_run_at.asc())
            .limit(50)
            .all()
        )

        for schedule in due:
            try:
                if schedule.last_scan is not None and schedule.last_scan.status in {
                    ScanStatus.PENDING,
                    ScanStatus.QUEUED,
                    ScanStatus.RUNNING,
                }:
                    # Avoid stacking while previous run is still active.
                    schedule.next_run_at = now + timedelta(minutes=5)
                    skipped += 1
                    continue

                if not schedule.assets:
                    schedule.last_error = "No assets linked to schedule"
                    schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
                    errors += 1
                    continue

                if schedule.engine not in {
                    ScannerEngine.NMAP,
                    ScannerEngine.NEXUSEC,
                    ScannerEngine.NUCLEI,
                }:
                    schedule.last_error = f"Engine {schedule.engine.value} not schedulable"
                    schedule.enabled = False
                    errors += 1
                    continue

                stamp = now.strftime("%Y-%m-%d %H:%M UTC")
                scan = Scan(
                    id=uuid4(),
                    organization_id=schedule.organization_id,
                    name=f"{schedule.name} · {stamp}",
                    scan_type=schedule.scan_type,
                    engine=schedule.engine,
                    status=ScanStatus.PENDING,
                    progress=0.0,
                    config={
                        **(schedule.config or {}),
                        "scheduled_from": str(schedule.id),
                    },
                    created_by_id=schedule.created_by_id,
                )
                session.add(scan)
                session.flush()

                for asset in schedule.assets:
                    session.add(ScanAsset(scan_id=scan.id, asset_id=asset.id))
                session.flush()
                # Commit before enqueue so the scanner worker can load the row.
                session.commit()

                task_id = _enqueue_scan(str(scan.id), schedule.engine.value)
                scan.status = ScanStatus.QUEUED
                scan.celery_task_id = task_id

                schedule.last_run_at = now
                schedule.last_scan_id = scan.id
                schedule.last_error = None
                schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
                session.add(scan)
                session.add(schedule)
                session.flush()
                dispatched += 1
                logger.info(
                    "Dispatched schedule %s → scan %s (task=%s)",
                    schedule.id,
                    scan.id,
                    task_id,
                )
            except Exception as exc:  # noqa: BLE001 — keep dispatcher resilient
                logger.exception("Failed to dispatch schedule %s", schedule.id)
                schedule.last_error = str(exc)[:500]
                schedule.next_run_at = now + timedelta(minutes=max(15, schedule.interval_minutes))
                errors += 1

        session.flush()

    return {
        "dispatched": dispatched,
        "skipped": skipped,
        "errors": errors,
        "checked_at": now.isoformat(),
    }
