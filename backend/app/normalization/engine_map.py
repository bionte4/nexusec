"""Map ScannerEngine → parser registry name."""

from __future__ import annotations

from app.core.enums import ScannerEngine

ENGINE_PARSER_NAMES: dict[ScannerEngine, str] = {
    ScannerEngine.NMAP: "nmap",
    ScannerEngine.NUCLEI: "nuclei",
    ScannerEngine.NEXUSEC: "nexusec",
    ScannerEngine.OPENVAS: "openvas",
    ScannerEngine.ZAP: "zap",
    ScannerEngine.OSINT: "osint",
    ScannerEngine.SARIF: "sarif",
    ScannerEngine.GENERIC: "generic",
    ScannerEngine.TRIVY: "trivy",
    ScannerEngine.BURP: "burp",
    ScannerEngine.NESSUS: "nessus",
}

IMPORTABLE_ENGINES: frozenset[ScannerEngine] = frozenset(ENGINE_PARSER_NAMES)

XML_IMPORT_ENGINES: frozenset[ScannerEngine] = frozenset(
    {
        ScannerEngine.NMAP,
        ScannerEngine.OPENVAS,
        ScannerEngine.BURP,
        ScannerEngine.NESSUS,
    }
)


def parser_name_for_engine(engine: ScannerEngine | str) -> str:
    if isinstance(engine, ScannerEngine):
        return ENGINE_PARSER_NAMES.get(engine, engine.value)
    key = str(engine).lower().strip()
    try:
        return ENGINE_PARSER_NAMES.get(ScannerEngine(key), key)
    except ValueError:
        return key
