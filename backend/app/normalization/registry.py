"""Parser registry — resolve parser by scanner engine / tool name."""

from __future__ import annotations

from typing import Dict

from app.normalization.base import FindingParser


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: Dict[str, FindingParser] = {}

    def register(self, parser: FindingParser) -> None:
        self._parsers[parser.name.lower()] = parser

    def get(self, name: str) -> FindingParser:
        key = name.lower().strip()
        if key not in self._parsers:
            raise KeyError(f"No parser registered for {name!r}")
        return self._parsers[key]

    def available(self) -> list[str]:
        return sorted(self._parsers.keys())


def build_default_registry() -> ParserRegistry:
    from app.normalization.parsers.custom_json import CustomJsonParser
    from app.normalization.parsers.nmap_xml import NmapXmlParser
    from app.normalization.parsers.nuclei_json import NucleiJsonParser
    from app.normalization.parsers.openvas_xml import OpenVasXmlParser

    registry = ParserRegistry()
    for parser in (
        NmapXmlParser(),
        NucleiJsonParser(),
        CustomJsonParser(),
        OpenVasXmlParser(),
    ):
        registry.register(parser)
    return registry
