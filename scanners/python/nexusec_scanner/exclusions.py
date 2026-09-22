"""Target exclusion lists (exact host, CIDR, domain suffix)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class ExclusionList:
    """
    Block scan targets that match:
    - exact IP / hostname
    - IPv4/IPv6 CIDR network
    - domain suffix (e.g. ``.internal.corp``)
    """

    hosts: set[str] = field(default_factory=set)
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    domain_suffixes: set[str] = field(default_factory=set)

    @classmethod
    def from_entries(cls, entries: Iterable[str]) -> ExclusionList:
        hosts: set[str] = set()
        networks: list[ipaddress._BaseNetwork] = []
        suffixes: set[str] = set()
        for raw in entries:
            item = (raw or "").strip().lower()
            if not item:
                continue
            if item.startswith("*."):
                suffixes.add(item[1:])  # .example.com
                continue
            if "/" in item:
                try:
                    networks.append(ipaddress.ip_network(item, strict=False))
                    continue
                except ValueError:
                    pass
            if item.startswith("."):
                suffixes.add(item)
                continue
            hosts.add(item)
        return cls(hosts=hosts, networks=networks, domain_suffixes=suffixes)

    def is_excluded(self, target: str) -> bool:
        key = (target or "").strip().lower()
        if not key:
            return True
        if key in self.hosts:
            return True
        try:
            ip = ipaddress.ip_address(key)
            if any(ip in net for net in self.networks):
                return True
        except ValueError:
            for suffix in self.domain_suffixes:
                if key.endswith(suffix) or key == suffix.lstrip("."):
                    return True
        return False
