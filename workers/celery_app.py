"""Celery application for distributed scan workers."""

from __future__ import annotations

import sys
from pathlib import Path

from celery import Celery

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.config import get_settings  # noqa: E402

settings = get_settings()

celery_app = Celery(
    "nexusec",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["workers.tasks", "workers.integration_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=60 * 30,  # hard kill at 30m
    task_soft_time_limit=60 * 25,
    broker_connection_retry_on_startup=True,
    # Isolate scan execution onto scanner-worker containers.
    task_default_queue="default",
    task_routes={
        "scans.*": {"queue": "scans"},
        "integrations.*": {"queue": "integrations"},
    },
)
