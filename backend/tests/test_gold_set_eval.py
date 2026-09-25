"""Gold-set evaluation tests for paper Scenario B (normalization) and C (remediation)."""

from __future__ import annotations

import json
from pathlib import Path

from app.core.enums import Severity
from app.normalization.fingerprint import compute_fingerprint
from app.normalization.registry import build_default_registry
from app.services.ai_remediation import VulnerabilityContext, mock_remediation

FIXTURES = Path(__file__).parent / "fixtures" / "gold"


def _load_labels(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_gold_scenario_b_normalization_agreement() -> None:
    labels = _load_labels("labels.json")
    registry = build_default_registry()
    parse_ok = 0
    severity_ok = 0
    severity_checks = 0
    field_ok = 0
    field_checks = 0

    for case in labels["cases"]:
        parser = registry.get(case["parser"])
        raw = (FIXTURES / case["fixture"]).read_text(encoding="utf-8")
        findings = parser.parse(raw)
        assert findings, f"{case['id']}: parser returned no findings"
        parse_ok += 1

        expect = case["expect"]
        assert len(findings) >= expect["min_findings"]
        assert all(f.source_tool == expect["source_tool"] for f in findings)
        assert all(f.name and f.severity for f in findings)
        field_checks += 1
        field_ok += 1

        if "must_include_ports" in expect:
            ports = {f.port for f in findings}
            for p in expect["must_include_ports"]:
                assert p in ports
            for p in expect.get("must_exclude_ports", []):
                assert p not in ports

        if "target_hint" in expect:
            assert all(f.target_hint == expect["target_hint"] for f in findings)

        for port_s, sev in (expect.get("severity_by_port") or {}).items():
            severity_checks += 1
            hit = next(f for f in findings if f.port == int(port_s))
            assert hit.severity == Severity(sev)
            severity_ok += 1

        for spec in expect.get("findings") or []:
            hit = next(
                (
                    f
                    for f in findings
                    if spec["match_name"].lower() in (f.name or "").lower()
                ),
                None,
            )
            assert hit is not None, f"{case['id']}: missing {spec['match_name']}"
            if "severity" in spec:
                severity_checks += 1
                assert hit.severity == Severity(spec["severity"])
                severity_ok += 1
            if "cve_id" in spec:
                assert hit.cve_id == spec["cve_id"]
            if "cwe_id" in spec:
                assert hit.cwe_id == spec["cwe_id"]
            if "port" in spec:
                assert hit.port == spec["port"]
            if "target_hint" in spec:
                assert hit.target_hint == spec["target_hint"]

        # Dedup stability: same fingerprint on re-parse
        again = parser.parse(raw)
        for a, b in zip(findings, again, strict=True):
            fa = compute_fingerprint(a, asset_key=a.target_hint or "")
            fb = compute_fingerprint(b, asset_key=b.target_hint or "")
            assert fa == fb

    assert parse_ok == len(labels["cases"])
    assert field_ok == field_checks
    assert severity_checks > 0
    assert severity_ok == severity_checks


def test_gold_scenario_c_remediation_structure() -> None:
    labels = _load_labels("remediation_labels.json")
    for case in labels["cases"]:
        ctx = VulnerabilityContext(
            title=case["id"],
            cwe_id=case["cwe_id"],
            description=case["description"],
            severity="high",
        )
        result = mock_remediation(ctx)
        md = (result.markdown or "").lower()
        assert result.markdown
        assert result.explanation
        assert result.remediation_steps
        assert result.patch_example
        assert (case["cwe_id"] or "") in (
            result.explanation + result.remediation_steps + result.patch_example
        )
        assert "remediation" in md
        assert "patch" in md
        assert "why this vulnerability" in md


def test_registry_includes_openvas() -> None:
    assert "openvas" in build_default_registry().available()
