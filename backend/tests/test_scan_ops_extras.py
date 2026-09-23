"""Unit tests for scan discovery host extraction and diff helpers."""

from __future__ import annotations

from app.services.scan_discovery_service import extract_nmap_hosts
from app.integrations.webhooks import mask_webhook_url, resolve_webhook_config


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="db.internal"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.6" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_extract_nmap_hosts_up_only() -> None:
    hosts = extract_nmap_hosts(SAMPLE_XML)
    assert len(hosts) == 1
    assert hosts[0]["ip_address"] == "10.0.0.5"
    assert hosts[0]["hostname"] == "db.internal"
    assert hosts[0]["open_ports"][0]["port"] == 22


def test_mask_webhook_url() -> None:
    masked = mask_webhook_url("https://hooks.slack.com/services/T00/B00/secret")
    assert masked.startswith("https://hooks.slack.com/")
    assert "secret" not in masked


def test_resolve_webhook_org_override() -> None:
    cfg = resolve_webhook_config(
        {
            "integrations": {
                "webhook": {
                    "enabled": True,
                    "provider": "slack",
                    "min_severity": "critical",
                    "urls": ["https://example.com/hook"],
                }
            }
        }
    )
    assert cfg["enabled"] is True
    assert cfg["provider"] == "slack"
    assert cfg["min_severity"] == "critical"
    assert cfg["urls"] == ["https://example.com/hook"]
    assert cfg["source"] == "organization"
