"""Nmap XML → NormalizedFinding parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional
from xml.etree.ElementTree import Element

from app.core.enums import Severity
from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding

# Heuristic severity for common risky open ports when no script output exists
_RISKY_PORTS = {
    21: Severity.MEDIUM,  # ftp
    23: Severity.HIGH,  # telnet
    445: Severity.HIGH,  # smb
    3389: Severity.HIGH,  # rdp
    5900: Severity.MEDIUM,  # vnc
}


class NmapXmlParser(FindingParser):
    name = "nmap"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        text = self._to_text(raw)
        if not text.strip():
            return []

        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid Nmap XML: {exc}") from exc

        findings: list[NormalizedFinding] = []
        for host in root.findall("host"):
            if not self._host_up(host):
                continue
            target = self._host_address(host) or "unknown"
            for port_el in host.findall("ports/port"):
                findings.extend(self._parse_port(port_el, target))
        return findings

    @staticmethod
    def _to_text(raw: RawInput) -> str:
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            return raw
        raise TypeError("NmapXmlParser expects XML string/bytes")

    @staticmethod
    def _host_up(host: Element) -> bool:
        status = host.find("status")
        if status is None:
            return True
        return status.attrib.get("state", "up") == "up"

    @staticmethod
    def _host_address(host: Element) -> Optional[str]:
        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") in {"ipv4", "ipv6"}:
                return addr.attrib.get("addr")
        hostname = host.find("hostnames/hostname")
        if hostname is not None:
            return hostname.attrib.get("name")
        return None

    def _parse_port(self, port_el: Element, target: str) -> list[NormalizedFinding]:
        state_el = port_el.find("state")
        if state_el is None or state_el.attrib.get("state") != "open":
            return []

        port_id = int(port_el.attrib.get("portid", "0"))
        protocol = port_el.attrib.get("protocol", "tcp")
        service_el = port_el.find("service")
        service_name = (
            service_el.attrib.get("name", "unknown") if service_el is not None else "unknown"
        )
        product = service_el.attrib.get("product") if service_el is not None else None
        version = service_el.attrib.get("version") if service_el is not None else None
        component = " ".join(x for x in [service_name, product, version] if x)

        findings: list[NormalizedFinding] = []

        # Script-based findings (NSE)
        for script in port_el.findall("script"):
            script_id = script.attrib.get("id", "script")
            output = script.attrib.get("output", "")
            severity = self._severity_from_script(script_id, output)
            findings.append(
                NormalizedFinding(
                    vuln_id=f"nmap:{script_id}:{protocol}/{port_id}",
                    name=f"Nmap script {script_id} on {protocol}/{port_id}",
                    description=output[:4000] or None,
                    severity=severity,
                    cvss_score=None,
                    cwe_id=None,
                    port=port_id,
                    protocol=protocol,
                    affected_component=component,
                    evidence={"script_id": script_id, "output": output[:2000]},
                    source_tool="nmap",
                    raw_source={"script": dict(script.attrib)},
                    target_hint=target,
                    pci_dss_requirement=["11.3.1"],
                    iso_27001_clause=["A.8.8"],
                )
            )

        # Always emit an open-port discovery finding
        severity = _RISKY_PORTS.get(port_id, Severity.INFO)
        findings.append(
            NormalizedFinding(
                vuln_id=f"nmap:open:{protocol}/{port_id}/{service_name}",
                name=f"Open port {protocol}/{port_id} ({service_name})",
                description=(
                    f"Nmap detected open {protocol}/{port_id} on {target} " f"running {component}."
                ),
                severity=severity,
                port=port_id,
                protocol=protocol,
                affected_component=component,
                evidence={
                    "state": "open",
                    "service": service_name,
                    "product": product,
                    "version": version,
                },
                source_tool="nmap",
                raw_source={
                    "port": dict(port_el.attrib),
                    "service": dict(service_el.attrib) if service_el is not None else {},
                },
                target_hint=target,
                mitre_tactics=["TA0043"],
                iso_27001_clause=["A.8.8"],
                pci_dss_requirement=["11.3.1"],
            )
        )
        return findings

    @staticmethod
    def _severity_from_script(script_id: str, output: str) -> Severity:
        blob = f"{script_id} {output}".lower()
        if any(k in blob for k in ("vuln", "cve-", "exploit", "critical")):
            return Severity.HIGH
        if any(k in blob for k in ("weak", "outdated", "deprecated", "ssl-heartbleed")):
            return Severity.MEDIUM
        return Severity.INFO
