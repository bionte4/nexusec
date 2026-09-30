"""OWASP ZAP mock wrapper + parser tests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_zap_wrapper_mock_parses() -> None:
    from app.normalization.parsers.zap_json import ZapJsonParser
    from workers.tool_wrappers.zap import ZapScanRequest, ZapWrapper

    wrapper = ZapWrapper(mode="mock")
    result = wrapper.run(
        ZapScanRequest(
            targets=["https://app.example.com"],
            scan_policy="baseline",
            mode="mock",
        )
    )
    assert result.returncode == 0
    assert result.stdout
    findings = ZapJsonParser().parse(result.stdout)
    assert len(findings) >= 1
    assert all(f.source_tool == "zap" for f in findings)


def test_zap_json_parser_alerts() -> None:
    from app.normalization.parsers.zap_json import ZapJsonParser

    raw = """
    {
      "site": [{
        "@host": "app.example.com",
        "alerts": [{
          "pluginid": "10021",
          "alertRef": "10021",
          "alert": "X-Content-Type-Options Header Missing",
          "name": "X-Content-Type-Options Header Missing",
          "riskcode": "1",
          "confidence": "2",
          "cweid": "693",
          "desc": "Missing header",
          "instances": [{"uri": "https://app.example.com/", "method": "GET"}]
        }]
      }]
    }
    """
    findings = ZapJsonParser().parse(raw)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-693"
    assert findings[0].source_tool == "zap"
    assert findings[0].name


def test_registry_includes_zap() -> None:
    from app.normalization.registry import build_default_registry

    assert "zap" in build_default_registry().available()
