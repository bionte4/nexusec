"""Celery health/heartbeat tasks for worker responsiveness probes."""

from __future__ import annotations

import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workers.celery_app import celery_app  # noqa: E402

logger = logging.getLogger(__name__)


@celery_app.task(name="observability.heartbeat", bind=True)
def worker_heartbeat(self) -> dict[str, Any]:
    """Lightweight ping task used to verify worker responsiveness."""
    hostname = getattr(getattr(self, "request", None), "hostname", None)
    tools = {name: shutil.which(name) is not None for name in ("nmap", "nuclei")}
    return {
        "ok": True,
        "worker": hostname,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "tools": tools,
    }


@celery_app.task(name="observability.tool_probe")
def tool_probe() -> dict[str, Any]:
    """Report scanner binary availability from the worker node."""
    result = {}
    for name in ("nmap", "nuclei"):
        path = shutil.which(name)
        result[name] = {"available": path is not None, "path": path}
    return {"checked_at": datetime.now(timezone.utc).isoformat(), "tools": result}
