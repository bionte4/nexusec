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
    from app.normalization.parsers.burp_xml import BurpXmlParser
    from app.normalization.parsers.custom_json import CustomJsonParser
    from app.normalization.parsers.generic_json import GenericJsonParser
    from app.normalization.parsers.nessus_xml import NessusXmlParser
    from app.normalization.parsers.nmap_xml import NmapXmlParser
    from app.normalization.parsers.nuclei_json import NucleiJsonParser
    from app.normalization.parsers.openvas_xml import OpenVasXmlParser
    from app.normalization.parsers.osint_json import OsintJsonParser
    from app.normalization.parsers.sarif_json import SarifParser
    from app.normalization.parsers.trivy_json import TrivyJsonParser
    from app.normalization.parsers.zap_json import ZapJsonParser

    registry = ParserRegistry()
    for parser in (
        NmapXmlParser(),
        NucleiJsonParser(),
        CustomJsonParser(),
        OpenVasXmlParser(),
        ZapJsonParser(),
        OsintJsonParser(),
        SarifParser(),
        GenericJsonParser(),
        TrivyJsonParser(),
        BurpXmlParser(),
        NessusXmlParser(),
    ):
        registry.register(parser)
    return registry
