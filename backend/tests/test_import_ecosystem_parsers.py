"""Import-ecosystem parsers: SARIF, generic, Trivy, Burp, Nessus (+ registry)."""

from __future__ import annotations

from pathlib import Path

from app.core.enums import Severity
from app.normalization.engine_map import IMPORTABLE_ENGINES, parser_name_for_engine
from app.normalization.parsers.burp_xml import BurpXmlParser
from app.normalization.parsers.generic_json import GenericJsonParser
from app.normalization.parsers.nessus_xml import NessusXmlParser
from app.normalization.parsers.sarif_json import SarifParser
from app.normalization.parsers.trivy_json import TrivyJsonParser
from app.normalization.registry import build_default_registry
from app.core.enums import ScannerEngine

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "import_ecosystem"


def test_registry_includes_import_ecosystem_parsers() -> None:
    names = set(build_default_registry().available())
    for expected in ("sarif", "generic", "trivy", "burp", "nessus", "nmap", "nuclei"):
        assert expected in names


def test_parser_name_for_engine_covers_imports() -> None:
    for eng in IMPORTABLE_ENGINES:
        assert parser_name_for_engine(eng) == eng.value


def test_sarif_parser() -> None:
    raw = (FIXTURES / "sample.sarif.json").read_text(encoding="utf-8")
    findings = SarifParser().parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "xss" in f.vuln_id.lower() or "XSS" in f.name or "xss" in f.name.lower()
    assert f.source_tool


def test_generic_json_aliases() -> None:
    raw = {
        "findings": [
            {
                "title": "Open Redis",
                "severity": "high",
                "host": "10.0.0.5",
                "port": 6379,
                "cwe": "CWE-306",
                "remediation": "Enable AUTH",
            }
        ]
    }
    findings = GenericJsonParser().parse(raw)
    assert len(findings) == 1
    assert findings[0].name == "Open Redis"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].port == 6379
    assert findings[0].remediation_steps == "Enable AUTH"


def test_trivy_parser() -> None:
    raw = (FIXTURES / "trivy_sample.json").read_text(encoding="utf-8")
    findings = TrivyJsonParser().parse(raw)
    assert findings
    assert any(f.cve_id and f.cve_id.startswith("CVE-") for f in findings)
    assert all(f.source_tool == "trivy" for f in findings)


def test_burp_parser() -> None:
    raw = (FIXTURES / "burp_sample.xml").read_text(encoding="utf-8")
    findings = BurpXmlParser().parse(raw)
    assert len(findings) >= 1
    assert findings[0].source_tool == "burp"
    assert findings[0].severity in {Severity.HIGH, Severity.MEDIUM, Severity.LOW}


def test_nessus_parser() -> None:
    raw = (FIXTURES / "nessus_sample.nessus").read_text(encoding="utf-8")
    findings = NessusXmlParser().parse(raw)
    assert findings
    assert findings[0].source_tool == "nessus"
    assert findings[0].target_hint


def test_core_gold_fixtures_still_parse() -> None:
    """P0 regression: existing gold samples remain loadable."""
    gold = Path(__file__).resolve().parent / "fixtures" / "gold"
    reg = build_default_registry()
    nmap = reg.get("nmap").parse((gold / "nmap_sample.xml").read_text(encoding="utf-8"))
    nuclei = reg.get("nuclei").parse(
        (gold / "nuclei_sample.jsonl").read_text(encoding="utf-8")
    )
    openvas = reg.get("openvas").parse(
        (gold / "openvas_sample.xml").read_text(encoding="utf-8")
    )
    assert nmap and nuclei and openvas
    assert ScannerEngine.SARIF.value == "sarif"
