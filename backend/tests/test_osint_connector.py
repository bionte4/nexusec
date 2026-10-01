"""OSINT connector + parser tests (offline; mocks crt.sh/RDAP HTTP)."""

from __future__ import annotations

import json
from unittest.mock import patch

from app.normalization.parsers.osint_json import OsintJsonParser
from app.normalization.registry import build_default_registry
from workers.tool_wrappers.osint import (
    OsintScanRequest,
    OsintWrapper,
    build_osint_report,
)


def test_registry_includes_osint() -> None:
    assert "osint" in build_default_registry().available()


def test_osint_parser_dns_and_subdomains() -> None:
    raw = json.dumps(
        {
            "engine": "osint",
            "results": [
                {
                    "target": "example.com",
                    "dns": {"A": ["93.184.216.34"], "AAAA": []},
                    "crtsh_subdomains": ["www.example.com", "mail.example.com"],
                    "rdap": {
                        "status": ["active"],
                        "nameservers": ["a.iana-servers.net"],
                        "events": [],
                    },
                }
            ],
        }
    )
    findings = OsintJsonParser().parse(raw)
    assert len(findings) >= 3
    assert all(f.source_tool == "osint" for f in findings)
    titles = " ".join(f.name for f in findings)
    assert "DNS" in titles
    assert "Certificate Transparency" in titles or "subdomain" in titles.lower()


def test_osint_wrapper_dns_only(monkeypatch) -> None:
    monkeypatch.setattr(
        "workers.tool_wrappers.osint._dns_lookup",
        lambda domain: {"A": ["1.2.3.4"], "AAAA": []},
    )
    monkeypatch.setattr(
        "workers.tool_wrappers.osint._crtsh_subdomains",
        lambda domain, timeout, limit: ["www.example.com"],
    )
    monkeypatch.setattr(
        "workers.tool_wrappers.osint._rdap_summary",
        lambda domain, timeout: {"status": ["active"], "nameservers": [], "events": []},
    )
    result = OsintWrapper().run(
        OsintScanRequest(
            targets=["example.com"],
            modules=["dns", "crtsh", "rdap"],
            timeout_seconds=10,
        )
    )
    assert result.returncode == 0
    assert result.tool_version
    findings = OsintJsonParser().parse(result.stdout)
    assert len(findings) >= 2


def test_build_osint_report_rejects_nothing_for_valid_domain() -> None:
    with patch(
        "workers.tool_wrappers.osint._dns_lookup",
        return_value={"A": ["9.9.9.9"], "AAAA": []},
    ), patch(
        "workers.tool_wrappers.osint._crtsh_subdomains",
        return_value=[],
    ), patch(
        "workers.tool_wrappers.osint._rdap_summary",
        return_value={"error": "skip"},
    ):
        raw = build_osint_report(
            ["example.com"],
            modules=["dns"],
            timeout_seconds=5,
        )
    data = json.loads(raw)
    assert data["engine"] == "osint"
    assert data["results"][0]["target"] == "example.com"
