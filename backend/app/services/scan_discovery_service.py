"""Extract discovered hosts from nmap scan results and register assets."""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import Any, Optional
from uuid import UUID
from xml.etree.ElementTree import Element

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import AssetCriticality, AssetType, ScannerEngine
from app.models.asset import Asset
from app.models.scan import Scan
from app.schemas.asset import AssetCreate, AssetRead
from app.services.asset_service import AssetService
from app.services.scan_result_utils import last_result
from app.services.scan_service import ScanNotFoundError, ScanValidationError


class ScanDiscoveryError(Exception):
    pass


def _host_up(host: Element) -> bool:
    status = host.find("status")
    if status is None:
        return True
    return status.attrib.get("state", "up") == "up"


def extract_nmap_hosts(xml_text: str) -> list[dict[str, Any]]:
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanDiscoveryError(f"Invalid Nmap XML: {exc}") from exc

    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        if not _host_up(host):
            continue
        ip_address: Optional[str] = None
        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") in {"ipv4", "ipv6"}:
                ip_address = addr.attrib.get("addr")
                break
        hostnames = [
            h.attrib.get("name")
            for h in host.findall("hostnames/hostname")
            if h.attrib.get("name")
        ]
        hostname = hostnames[0] if hostnames else None
        open_ports: list[dict[str, Any]] = []
        for port_el in host.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            service_el = port_el.find("service")
            open_ports.append(
                {
                    "port": int(port_el.attrib.get("portid", "0")),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "service": (
                        service_el.attrib.get("name") if service_el is not None else None
                    ),
                }
            )
        if not ip_address and not hostname:
            continue
        hosts.append(
            {
                "ip_address": ip_address,
                "hostname": hostname,
                "domains": [],
                "open_ports": open_ports,
            }
        )
    return hosts


class ScanDiscoveryService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def discovered_hosts(
        self, scan_id: UUID, *, organization_id: Optional[UUID] = None
    ) -> dict[str, Any]:
        scan = await self._get_scan(scan_id, organization_id=organization_id)
        if scan.engine != ScannerEngine.NMAP:
            raise ScanDiscoveryError("Host discovery is only available for nmap scans")

        result = last_result(scan)
        xml_text = result.get("stdout_xml") or ""
        if not isinstance(xml_text, str) or not xml_text.strip():
            raise ScanDiscoveryError("Scan has no nmap XML in last_result")

        raw_hosts = extract_nmap_hosts(xml_text)
        org_id = scan.organization_id
        seed_ids = {a.id for a in (scan.assets or [])}

        # Load org assets for matching (cap for safety)
        assets = list(
            (
                await self.db.execute(
                    select(Asset)
                    .where(Asset.organization_id == org_id)
                    .limit(2000)
                )
            )
            .scalars()
            .all()
        )

        out: list[dict[str, Any]] = []
        for host in raw_hosts[:500]:
            matched = self._match_asset(host, assets)
            already = matched is not None
            matched_id = matched.id if matched else None
            if matched_id in seed_ids:
                already = True

            ip = host.get("ip_address")
            hostname = host.get("hostname")
            if ip:
                suggested = {
                    "name": hostname or ip,
                    "asset_type": "ip",
                    "ip_address": ip,
                    "hostname": hostname,
                    "criticality": "medium",
                }
            else:
                suggested = {
                    "name": hostname,
                    "asset_type": "domain",
                    "domain": hostname,
                    "hostname": hostname,
                    "criticality": "medium",
                }

            out.append(
                {
                    **host,
                    "already_known": already,
                    "matched_asset_id": str(matched_id) if matched_id else None,
                    "suggested_asset": suggested,
                }
            )

        return {
            "scan_id": str(scan.id),
            "total": len(out),
            "new_count": sum(1 for h in out if not h["already_known"]),
            "hosts": out,
        }

    async def accept_hosts(
        self,
        scan_id: UUID,
        hosts: list[dict[str, Any]],
        *,
        organization_id: UUID,
        created_by_id: Optional[UUID] = None,
    ) -> dict[str, Any]:
        scan = await self._get_scan(scan_id, organization_id=organization_id)
        if scan.engine != ScannerEngine.NMAP:
            raise ScanDiscoveryError("Host discovery is only available for nmap scans")
        if scan.organization_id != organization_id:
            raise ScanValidationError("Organization mismatch")

        asset_svc = AssetService(self.db)
        created: list[AssetRead] = []
        skipped: list[dict[str, str]] = []

        for item in hosts[:100]:
            ip = (item.get("ip_address") or "").strip() or None
            hostname = (item.get("hostname") or "").strip() or None
            name = (item.get("name") or hostname or ip or "").strip()
            if not name:
                skipped.append({"reason": "missing name/ip/hostname"})
                continue

            existing = await self._find_duplicate(
                organization_id=organization_id, ip=ip, hostname=hostname
            )
            if existing is not None:
                skipped.append(
                    {
                        "ip": ip or "",
                        "hostname": hostname or "",
                        "reason": "duplicate",
                        "asset_id": str(existing.id),
                    }
                )
                continue

            crit_raw = item.get("criticality") or AssetCriticality.MEDIUM.value
            try:
                criticality = AssetCriticality(crit_raw)
            except ValueError:
                criticality = AssetCriticality.MEDIUM

            if ip:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    skipped.append({"ip": ip, "reason": "invalid_ip"})
                    continue
                payload = AssetCreate(
                    name=name,
                    asset_type=AssetType.IP,
                    criticality=criticality,
                    ip_address=ip,
                    hostname=hostname,
                )
            elif hostname:
                payload = AssetCreate(
                    name=name,
                    asset_type=AssetType.DOMAIN,
                    criticality=criticality,
                    domain=hostname,
                    hostname=hostname,
                )
            else:
                skipped.append({"reason": "no ip or hostname"})
                continue

            created.append(
                await asset_svc.create(
                    payload,
                    organization_id=organization_id,
                    created_by_id=created_by_id,
                )
            )

        return {
            "scan_id": str(scan.id),
            "created": [c.model_dump(mode="json") for c in created],
            "skipped": skipped,
            "created_count": len(created),
            "skipped_count": len(skipped),
        }

    async def _get_scan(
        self, scan_id: UUID, *, organization_id: Optional[UUID]
    ) -> Scan:
        stmt = (
            select(Scan)
            .options(selectinload(Scan.assets))
            .where(Scan.id == scan_id)
        )
        if organization_id is not None:
            stmt = stmt.where(Scan.organization_id == organization_id)
        scan = (await self.db.execute(stmt)).scalar_one_or_none()
        if scan is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")
        return scan

    @staticmethod
    def _match_asset(host: dict[str, Any], assets: list[Asset]) -> Optional[Asset]:
        ip = (host.get("ip_address") or "").lower()
        hostname = (host.get("hostname") or "").lower()
        for asset in assets:
            if ip and asset.ip_address and str(asset.ip_address).lower() == ip:
                return asset
            if hostname and asset.hostname and asset.hostname.lower() == hostname:
                return asset
            if hostname and asset.domain and asset.domain.lower() == hostname:
                return asset
        return None

    async def _find_duplicate(
        self,
        *,
        organization_id: UUID,
        ip: Optional[str],
        hostname: Optional[str],
    ) -> Optional[Asset]:
        clauses = []
        if ip:
            clauses.append(Asset.ip_address == ip)
        if hostname:
            clauses.append(Asset.hostname == hostname)
            clauses.append(Asset.domain == hostname)
        if not clauses:
            return None
        stmt = (
            select(Asset)
            .where(Asset.organization_id == organization_id, or_(*clauses))
            .limit(1)
        )
        return (await self.db.execute(stmt)).scalar_one_or_none()
