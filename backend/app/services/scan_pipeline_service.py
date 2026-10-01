"""VA pipeline — discovery then vulnerability assessment on the same assets."""

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.enums import ScanStatus, ScanType, ScannerEngine
from app.models.scan import Scan, ScanAsset
from app.services.scan_policy import assert_roe_for_scan, assert_production_scanner_config
from app.services.scan_service import (
    ScanService,
    ScanValidationError,
    _to_read,
)


_VA_ENGINES = frozenset(
    {
        ScannerEngine.NUCLEI,
        ScannerEngine.NEXUSEC,
        ScannerEngine.OPENVAS,
        # ZAP is import-first for production VA; live daemon not enabled.
        ScannerEngine.ZAP,
    }
)


class PipelineCreateError(Exception):
    pass


def default_va_config(engine: ScannerEngine) -> dict[str, Any]:
    """Sensible VA defaults. Production prefers live/import — not mock."""
    if engine == ScannerEngine.NUCLEI:
        return {
            "severity": ["critical", "high", "medium"],
            "tags": ["cve", "misconfig", "vuln", "exposure"],
            "exclude_tags": ["dos"],
            "rate_limit": 25,
            "concurrency": 10,
            "bulk_size": 10,
            "template_dirs": [
                "/opt/nuclei-templates/http",
                "/opt/nuclei-templates/ssl",
                "/opt/nuclei-templates/network",
            ],
        }
    if engine == ScannerEngine.OPENVAS:
        # Prefer live GMP; mock only with explicit lab_mode (blocked in prod otherwise).
        return {
            "openvas_mode": "gmp",
            "openvas_catalogs": ["webserver", "dbserver", "appserver"],
        }
    if engine == ScannerEngine.ZAP:
        # Import-first: set report_json via Import UI, or lab_mode+mock for demos.
        return {"zap_mode": "import", "zap_policy": "baseline"}
    return {}


def _zap_pipeline_ready(cfg: dict[str, Any]) -> bool:
    if cfg.get("lab_mode") is True:
        return True
    if isinstance(cfg.get("report_json"), str) and cfg["report_json"].strip():
        return True
    return False


class ScanPipelineService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.scans = ScanService(db)

    async def create(
        self,
        *,
        organization_id: UUID,
        created_by_id: Optional[UUID],
        name: str,
        asset_ids: list[UUID],
        va_engine: ScannerEngine = ScannerEngine.NUCLEI,
        va_config: Optional[dict[str, Any]] = None,
        discovery_engine: ScannerEngine = ScannerEngine.NMAP,
    ) -> dict[str, Any]:
        if discovery_engine != ScannerEngine.NMAP:
            raise PipelineCreateError("Pipeline discovery currently supports nmap only")
        if va_engine not in _VA_ENGINES:
            raise PipelineCreateError(
                f"Pipeline VA engine must be one of: "
                f"{', '.join(sorted(e.value for e in _VA_ENGINES))}"
            )

        assets = await self.scans._load_assets(asset_ids, organization_id=organization_id)
        if len(assets) != len(set(asset_ids)):
            raise ScanValidationError("One or more asset_ids were not found")
        ScanService._ensure_scan_targets(assets, engine=discovery_engine)
        ScanService._ensure_scan_targets(assets, engine=va_engine)

        pipeline_id = str(uuid4())
        label = (name or "VA pipeline").strip() or "VA pipeline"
        va_cfg = {**default_va_config(va_engine), **(va_config or {})}
        try:
            assert_roe_for_scan(va_cfg, settings=get_settings())
            assert_production_scanner_config(
                va_engine, va_cfg, settings=get_settings()
            )
        except ValueError as exc:
            raise ScanValidationError(str(exc)) from exc

        if va_engine == ScannerEngine.ZAP and not _zap_pipeline_ready(va_cfg):
            raise ScanValidationError(
                "Pipeline ZAP requires imported report_json or lab_mode=true. "
                "Prefer VA engine nuclei, or use Import scanner report for ZAP JSON."
            )
        roe_flags = {
            "roe_acknowledged": bool(va_cfg.get("roe_acknowledged") is True),
            "lab_mode": bool(va_cfg.get("lab_mode") is True),
        }
        if va_cfg.get("notes"):
            roe_flags["notes"] = va_cfg.get("notes")

        discovery = Scan(
            organization_id=organization_id,
            name=f"{label} · discovery",
            scan_type=ScanType.DISCOVERY,
            engine=discovery_engine,
            status=ScanStatus.PENDING,
            progress=0.0,
            config={
                "pipeline_id": pipeline_id,
                "pipeline_role": "discovery",
                "port_preset": "common_va",
                "nmap_scripts": [
                    "banner",
                    "http-title",
                    "http-server-header",
                    "ssl-cert",
                    "mysql-info",
                ],
                **roe_flags,
            },
            created_by_id=created_by_id,
        )
        self.db.add(discovery)
        await self.db.flush()

        follow_up = Scan(
            organization_id=organization_id,
            name=f"{label} · va ({va_engine.value})",
            scan_type=ScanType.VA,
            engine=va_engine,
            status=ScanStatus.PENDING,
            progress=0.0,
            config={
                **va_cfg,
                "pipeline_id": pipeline_id,
                "pipeline_role": "va",
                "pipeline_wait_for": str(discovery.id),
            },
            created_by_id=created_by_id,
        )
        self.db.add(follow_up)
        await self.db.flush()

        discovery_cfg = dict(discovery.config or {})
        discovery_cfg["pipeline_next_scan_id"] = str(follow_up.id)
        discovery.config = discovery_cfg
        self.db.add(discovery)

        for asset in assets:
            self.db.add(ScanAsset(scan_id=discovery.id, asset_id=asset.id))
            self.db.add(ScanAsset(scan_id=follow_up.id, asset_id=asset.id))
        await self.db.flush()

        # enqueue commits discovery + follow_up so both rows exist before nmap.delay()
        task_id = await self.scans.enqueue(
            discovery.id, engine=discovery.engine, actor_id=created_by_id
        )

        discovery = await self.scans._get_scan(discovery.id)
        follow_up = await self.scans._get_scan(follow_up.id)
        return {
            "pipeline_id": pipeline_id,
            "discovery": _to_read(discovery),
            "va": _to_read(follow_up),
            "celery_task_id": task_id,
            "message": (
                f"Pipeline started: discovery queued ({task_id}); "
                f"VA ({va_engine.value}) waits for discovery completion"
            ),
        }


class ScanImportService:
    """Create a completed scan from imported raw scanner output and ingest."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.scans = ScanService(db)

    async def import_report(
        self,
        *,
        organization_id: UUID,
        created_by_id: Optional[UUID],
        name: str,
        engine: ScannerEngine,
        asset_ids: list[UUID],
        raw: str,
    ) -> dict[str, Any]:
        from datetime import datetime, timezone

        from app.services.normalization_service import (
            NormalizationError,
            normalize_scan_raw_result,
        )

        from app.normalization.engine_map import (
            IMPORTABLE_ENGINES,
            XML_IMPORT_ENGINES,
        )

        if engine not in IMPORTABLE_ENGINES:
            raise ScanValidationError(f"Import not supported for engine {engine.value}")

        raw = (raw or "").strip()
        if not raw:
            raise ScanValidationError("raw report content is required")
        if len(raw) > 2_000_000:
            raise ScanValidationError("raw report exceeds 2MB limit")

        assets = await self.scans._load_assets(asset_ids, organization_id=organization_id)
        if len(assets) != len(set(asset_ids)):
            raise ScanValidationError("One or more asset_ids were not found")

        # Validate parse before creating the row
        from app.services.normalization_service import NormalizationService

        try:
            findings = NormalizationService().parse(engine, raw, enrich=True)
        except (NormalizationError, ValueError, TypeError) as exc:
            raise ScanValidationError(f"Invalid report for {engine.value}: {exc}") from exc

        now = datetime.now(timezone.utc)
        if engine in XML_IMPORT_ENGINES:
            result_key = "stdout_xml"
        elif engine == ScannerEngine.NUCLEI:
            result_key = "stdout_jsonl"
        else:
            result_key = "stdout_json"
        import_config: dict[str, Any] = {
            "imported": True,
            "last_result": {
                "engine": engine.value,
                result_key: raw,
                "finished_at": now.isoformat(),
                "command": ["import", engine.value],
            },
        }
        # Preserve real-report markers so mock-policy treats imports as evidence.
        if engine == ScannerEngine.ZAP:
            import_config["report_json"] = raw
            import_config["zap_mode"] = "import"
        elif engine == ScannerEngine.OPENVAS:
            import_config["report_xml"] = raw
            import_config["openvas_mode"] = "import"
        scan = Scan(
            organization_id=organization_id,
            name=(name or f"Import ({engine.value})").strip()[:255],
            scan_type=(
                ScanType.DISCOVERY
                if engine in {ScannerEngine.NMAP, ScannerEngine.OSINT}
                else ScanType.VA
            ),
            engine=engine,
            status=ScanStatus.COMPLETED,
            progress=100.0,
            config=import_config,
            created_by_id=created_by_id,
            started_at=now,
            completed_at=now,
        )
        self.db.add(scan)
        await self.db.flush()
        for asset in assets:
            self.db.add(ScanAsset(scan_id=scan.id, asset_id=asset.id))
        await self.db.flush()

        try:
            ingest = await normalize_scan_raw_result(
                self.db, scan.id, raw=raw, engine=engine
            )
        except NormalizationError as exc:
            raise ScanValidationError(str(exc)) from exc

        # Persist ingest stats on last_result
        cfg = dict(scan.config or {})
        last = dict(cfg.get("last_result") or {})
        last["ingest"] = {
            "inserted": ingest.get("inserted", 0),
            "updated": ingest.get("updated", 0),
            "skipped": ingest.get("skipped", 0),
        }
        cfg["last_result"] = last
        scan.config = cfg
        self.db.add(scan)
        await self.db.flush()

        scan = await self.scans._get_scan(scan.id)
        return {
            "scan": _to_read(scan),
            "finding_count": len(findings),
            "ingest": last["ingest"],
            "message": f"Imported {engine.value} report and ingested findings",
        }
