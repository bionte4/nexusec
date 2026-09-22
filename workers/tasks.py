"""Celery tasks for asynchronous security scans."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from sqlalchemy.orm import Session, selectinload

from app.core.enums import AssetType, ScanStatus, ScannerEngine
from app.models.asset import Asset
from app.models.scan import Scan
from workers.celery_app import celery_app
from workers.db import session_scope
from workers.tool_wrappers.base import (
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
)
from workers.tool_wrappers.nmap import DEFAULT_NMAP_FLAGS, NmapScanRequest, NmapWrapper
from workers.tool_wrappers.nuclei import NucleiScanRequest, NucleiWrapper

logger = logging.getLogger(__name__)

# Cap stored XML to avoid blowing up JSONB rows
_MAX_RESULT_CHARS = 200_000


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _targets_from_assets(assets: list[Asset]) -> list[str]:
    from workers.tool_wrappers.validators import coerce_host

    targets: list[str] = []
    for asset in assets:
        raw: str | None = None
        if asset.asset_type == AssetType.IP and asset.ip_address:
            raw = str(asset.ip_address)
        elif asset.asset_type == AssetType.DOMAIN and asset.domain:
            raw = asset.domain
        elif asset.hostname:
            raw = asset.hostname
        elif asset.domain:
            raw = asset.domain
        elif asset.ip_address:
            raw = str(asset.ip_address)
        elif getattr(asset, "url", None):
            raw = asset.url
        if not raw:
            continue
        try:
            targets.append(coerce_host(raw))
        except Exception:  # noqa: BLE001 — skip bad rows; wrapper will fail if empty
            logger.warning("Skipping unscannable asset target: %r", raw)
    seen: set[str] = set()
    unique: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def _nuclei_targets_from_assets(assets: list[Asset]) -> list[str]:
    """Prefer explicit URL; otherwise derive http(s) endpoints from domain/IP."""
    from workers.tool_wrappers.nuclei import validate_nuclei_target
    from workers.tool_wrappers.validators import TargetValidationError

    targets: list[str] = []
    for asset in assets:
        candidates: list[str] = []
        url = (getattr(asset, "url", None) or "").strip()
        if url:
            candidates.append(url)
        elif asset.domain:
            # domain may accidentally contain a full URL — normalize later
            domain = asset.domain.strip()
            candidates.append(domain if "://" in domain else f"https://{domain}")
        elif asset.hostname:
            host = asset.hostname.strip()
            candidates.append(host if "://" in host else f"https://{host}")
        elif asset.ip_address:
            candidates.append(f"http://{asset.ip_address}")
        for c in candidates:
            try:
                targets.append(validate_nuclei_target(c))
            except TargetValidationError:
                logger.warning("Skipping invalid Nuclei target: %r", c)
    seen: set[str] = set()
    unique: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def _update_scan(
    session: Session,
    scan: Scan,
    *,
    status: ScanStatus,
    progress: Optional[float] = None,
    error_message: Optional[str] = None,
    result_payload: Optional[dict[str, Any]] = None,
    mark_started: bool = False,
    mark_completed: bool = False,
) -> None:
    scan.status = status
    if progress is not None:
        scan.progress = progress
    if error_message is not None:
        scan.error_message = error_message
    if mark_started and scan.started_at is None:
        scan.started_at = _utcnow()
    if mark_completed:
        scan.completed_at = _utcnow()
    if result_payload is not None:
        config = dict(scan.config or {})
        config["last_result"] = result_payload
        scan.config = config
    session.add(scan)
    session.flush()


def _normalize_and_ingest(session: Session, *, scan: Scan, engine: ScannerEngine, raw_output):
    """Parse raw scanner output and upsert vulnerabilities for the scan's assets."""
    from app.normalization import (
        AssetResolver,
        FindingIngestionService,
        build_default_registry,
    )

    registry = build_default_registry()
    parser_name = {
        ScannerEngine.NMAP: "nmap",
        ScannerEngine.NUCLEI: "nuclei",
        ScannerEngine.NEXUSEC: "nexusec",
    }.get(engine, engine.value)

    try:
        parser = registry.get(parser_name)
    except KeyError:
        logger.warning("No parser for engine %s — skipping ingest", engine)
        from app.normalization.ingest import IngestStats

        return IngestStats(skipped=0)

    findings = parser.parse(raw_output)
    resolver = AssetResolver.from_assets(list(scan.assets))
    default_asset = scan.assets[0].id if scan.assets else None
    service = FindingIngestionService(session)
    return service.ingest(
        scan_id=scan.id,
        findings=findings,
        resolver=resolver,
        organization_id=scan.organization_id,
        default_asset_id=default_asset,
    )


def _scanner_python_path() -> None:
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    scanner_path = root / "scanners" / "python"
    if str(scanner_path) not in sys.path:
        sys.path.insert(0, str(scanner_path))


@celery_app.task(name="scans.run_nexusec", bind=True, max_retries=0)
def run_nexusec_scan(self, scan_id: str) -> dict[str, Any]:
    """Run the custom asyncio NexuSec scanner engine and ingest findings."""
    _scanner_python_path()
    from nexusec_scanner import ExclusionList, ScanConfig, run_scan_sync

    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        return {"scan_id": scan_id, "status": "failed", "error": "invalid scan_id"}

    with session_scope() as session:
        scan = (
            session.query(Scan)
            .options(selectinload(Scan.assets))
            .filter(Scan.id == scan_uuid)
            .one_or_none()
        )
        if scan is None:
            return {"scan_id": scan_id, "status": "failed", "error": "scan not found"}

        scan.celery_task_id = self.request.id
        _update_scan(
            session,
            scan,
            status=ScanStatus.RUNNING,
            progress=5.0,
            mark_started=True,
            error_message=None,
        )

        targets = _targets_from_assets(list(scan.assets))
        if not targets:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message="No valid IP/domain targets on linked assets",
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": "no targets"}

        cfg = scan.config or {}
        from nexusec_scanner import DEFAULT_PORTS

        ports = cfg.get("ports") or list(DEFAULT_PORTS)
        exclusions = ExclusionList.from_entries(cfg.get("exclusions") or [])
        config = ScanConfig(
            ports=[int(p) for p in ports],
            connect_timeout=float(cfg.get("connect_timeout") or 1.5),
            grab_banner=bool(cfg.get("grab_banner", True)),
            max_concurrent_probes=int(cfg.get("max_concurrent_probes") or 50),
            rate_per_second=float(cfg.get("rate_per_second") or 25.0),
            burst=int(cfg.get("burst") or 15),
            circuit_failure_threshold=int(cfg.get("circuit_failure_threshold") or 5),
            exclusions=exclusions,
        )

        try:
            report = run_scan_sync(targets, config=config)
        except Exception as exc:  # noqa: BLE001
            logger.exception("NexuSec scanner failed")
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message=str(exc),
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": str(exc)}

        payload = {
            "engine": ScannerEngine.NEXUSEC.value,
            "targets": targets,
            "stats": report.stats,
            "targets_excluded": report.targets_excluded,
            "targets_circuit_open": report.targets_circuit_open,
            "findings": report.findings,
            "finished_at": _utcnow().isoformat(),
        }

        ingest_stats = _normalize_and_ingest(
            session,
            scan=scan,
            engine=ScannerEngine.NEXUSEC,
            raw_output={"findings": report.findings},
        )
        payload["ingest"] = {
            "inserted": ingest_stats.inserted,
            "updated": ingest_stats.updated,
            "skipped": ingest_stats.skipped,
            "unmatched_targets": ingest_stats.unmatched_targets[:20],
        }

        _update_scan(
            session,
            scan,
            status=ScanStatus.COMPLETED,
            progress=100.0,
            error_message=None,
            result_payload=payload,
            mark_completed=True,
        )
        return {
            "scan_id": scan_id,
            "status": "completed",
            "targets": targets,
            "stats": report.stats,
            "ingest": payload["ingest"],
        }


@celery_app.task(name="scans.run_nmap", bind=True, max_retries=0)
def run_nmap_scan(self, scan_id: str) -> dict[str, Any]:
    """
    Execute an asynchronous Nmap job and persist status/results on the Scan row.
    """
    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        logger.error("Invalid scan_id: %s", scan_id)
        return {"scan_id": scan_id, "status": "failed", "error": "invalid scan_id"}

    with session_scope() as session:
        scan = (
            session.query(Scan)
            .options(selectinload(Scan.assets))
            .filter(Scan.id == scan_uuid)
            .one_or_none()
        )
        if scan is None:
            return {"scan_id": scan_id, "status": "failed", "error": "scan not found"}

        scan.celery_task_id = self.request.id
        _update_scan(
            session,
            scan,
            status=ScanStatus.RUNNING,
            progress=5.0,
            mark_started=True,
            error_message=None,
        )

        targets = _targets_from_assets(list(scan.assets))
        if not targets:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message="No valid IP/domain targets on linked assets",
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": "no targets"}

        cfg = scan.config or {}
        flags = cfg.get("nmap_flags") or list(DEFAULT_NMAP_FLAGS)
        timeout = int(cfg.get("timeout_seconds") or 600)

        try:
            wrapper = NmapWrapper()
            result = wrapper.run(
                NmapScanRequest(
                    targets=targets,
                    flags=flags,
                    timeout_seconds=timeout,
                )
            )
        except ToolNotFoundError as exc:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message=str(exc),
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": str(exc)}
        except ToolTimeoutError as exc:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message=str(exc),
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": str(exc)}
        except ToolExecutionError as exc:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message=str(exc),
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": str(exc)}

        stdout = result.stdout
        truncated = False
        if len(stdout) > _MAX_RESULT_CHARS:
            stdout = stdout[:_MAX_RESULT_CHARS]
            truncated = True

        payload = {
            "engine": ScannerEngine.NMAP.value,
            "targets": targets,
            "returncode": result.returncode,
            "command": list(result.command),
            "stdout_xml": stdout,
            "stderr": (result.stderr or "")[:10_000],
            "truncated": truncated,
            "finished_at": _utcnow().isoformat(),
        }

        if result.returncode != 0:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message=f"nmap exited with code {result.returncode}",
                result_payload=payload,
                mark_completed=True,
            )
            return {
                "scan_id": scan_id,
                "status": "failed",
                "returncode": result.returncode,
            }

        ingest_stats = _normalize_and_ingest(
            session,
            scan=scan,
            engine=ScannerEngine.NMAP,
            raw_output=stdout,
        )
        payload["ingest"] = {
            "inserted": ingest_stats.inserted,
            "updated": ingest_stats.updated,
            "skipped": ingest_stats.skipped,
            "unmatched_targets": ingest_stats.unmatched_targets[:20],
        }

        _update_scan(
            session,
            scan,
            status=ScanStatus.COMPLETED,
            progress=100.0,
            error_message=None,
            result_payload=payload,
            mark_completed=True,
        )
        return {
            "scan_id": scan_id,
            "status": "completed",
            "targets": targets,
            "returncode": 0,
            "ingest": payload["ingest"],
        }


@celery_app.task(name="scans.run_nuclei", bind=True, max_retries=0)
def run_nuclei_scan(self, scan_id: str) -> dict[str, Any]:
    """Execute Nuclei JSONL scan and ingest normalized findings."""
    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        logger.error("Invalid scan_id: %s", scan_id)
        return {"scan_id": scan_id, "status": "failed", "error": "invalid scan_id"}

    with session_scope() as session:
        scan = (
            session.query(Scan)
            .options(selectinload(Scan.assets))
            .filter(Scan.id == scan_uuid)
            .one_or_none()
        )
        if scan is None:
            return {"scan_id": scan_id, "status": "failed", "error": "scan not found"}

        scan.celery_task_id = self.request.id
        _update_scan(
            session,
            scan,
            status=ScanStatus.RUNNING,
            progress=5.0,
            mark_started=True,
            error_message=None,
        )

        targets = _nuclei_targets_from_assets(list(scan.assets))
        if not targets:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message="No valid URL/domain/IP targets on linked assets",
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": "no targets"}

        cfg = scan.config or {}
        severities = cfg.get("severity") or cfg.get("severities") or [
            "critical",
            "high",
            "medium",
        ]
        tags = cfg.get("tags") or []
        exclude_tags = cfg.get("exclude_tags") or cfg.get("etags") or ["dos"]
        rate_limit = int(cfg.get("rate_limit") or 50)
        timeout = int(cfg.get("timeout_seconds") or 900)
        template_dir = str(cfg.get("template_dir") or "/opt/nuclei-templates")

        try:
            wrapper = NucleiWrapper()
            result = wrapper.run(
                NucleiScanRequest(
                    targets=targets,
                    severities=list(severities),
                    tags=list(tags),
                    exclude_tags=list(exclude_tags),
                    rate_limit=rate_limit,
                    timeout_seconds=timeout,
                    template_dir=template_dir,
                )
            )
        except ToolNotFoundError as exc:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message=str(exc),
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": str(exc)}
        except ToolTimeoutError as exc:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message=str(exc),
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": str(exc)}
        except ToolExecutionError as exc:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message=str(exc),
                mark_completed=True,
            )
            return {"scan_id": scan_id, "status": "failed", "error": str(exc)}

        stdout = result.stdout
        truncated = False
        if len(stdout) > _MAX_RESULT_CHARS:
            stdout = stdout[:_MAX_RESULT_CHARS]
            truncated = True

        payload = {
            "engine": ScannerEngine.NUCLEI.value,
            "targets": targets,
            "returncode": result.returncode,
            "command": list(result.command),
            "stdout_jsonl": stdout,
            "stderr": (result.stderr or "")[:10_000],
            "truncated": truncated,
            "finished_at": _utcnow().isoformat(),
        }

        # Nuclei returns 0 even with findings; non-zero indicates tool failure.
        if result.returncode != 0:
            _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                progress=100.0,
                error_message=f"nuclei exited with code {result.returncode}",
                result_payload=payload,
                mark_completed=True,
            )
            return {
                "scan_id": scan_id,
                "status": "failed",
                "returncode": result.returncode,
            }

        ingest_stats = _normalize_and_ingest(
            session,
            scan=scan,
            engine=ScannerEngine.NUCLEI,
            raw_output=stdout,
        )
        payload["ingest"] = {
            "inserted": ingest_stats.inserted,
            "updated": ingest_stats.updated,
            "skipped": ingest_stats.skipped,
            "unmatched_targets": ingest_stats.unmatched_targets[:20],
        }

        _update_scan(
            session,
            scan,
            status=ScanStatus.COMPLETED,
            progress=100.0,
            error_message=None,
            result_payload=payload,
            mark_completed=True,
        )
        return {
            "scan_id": scan_id,
            "status": "completed",
            "targets": targets,
            "returncode": 0,
            "ingest": payload["ingest"],
        }


@celery_app.task(name="scans.run_scan", bind=True)
def run_scan(self, scan_id: str) -> dict[str, Any]:
    """Dispatcher — routes to engine-specific Celery tasks."""
    with session_scope() as session:
        try:
            scan_uuid = UUID(scan_id)
        except ValueError:
            return {"scan_id": scan_id, "status": "failed", "error": "invalid scan_id"}
        scan = session.get(Scan, scan_uuid)
        if scan is None:
            return {"scan_id": scan_id, "status": "failed", "error": "scan not found"}
        engine = scan.engine

    if engine == ScannerEngine.NMAP:
        async_result = run_nmap_scan.delay(scan_id)
        return {
            "scan_id": scan_id,
            "status": "delegated",
            "engine": engine.value,
            "task_id": async_result.id,
        }

    if engine == ScannerEngine.NEXUSEC:
        async_result = run_nexusec_scan.delay(scan_id)
        return {
            "scan_id": scan_id,
            "status": "delegated",
            "engine": engine.value,
            "task_id": async_result.id,
        }

    if engine == ScannerEngine.NUCLEI:
        async_result = run_nuclei_scan.delay(scan_id)
        return {
            "scan_id": scan_id,
            "status": "delegated",
            "engine": engine.value,
            "task_id": async_result.id,
        }

    return {
        "scan_id": scan_id,
        "status": "failed",
        "error": f"Engine {engine} not implemented yet",
    }
