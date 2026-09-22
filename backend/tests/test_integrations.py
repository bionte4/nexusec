"""Unit tests for webhooks, ticketing, and SIEM exporters."""

from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.core.enums import FindingStatus, Severity
from app.integrations.common import finding_payload, severity_rank
from app.integrations.siem import SiemForwarder, to_cef, to_json_syslog
from app.integrations.ticketing import (
    JiraTicketClient,
    NullTicketClient,
    ServiceNowTicketClient,
    sync_critical_ticket,
)
from app.integrations.webhooks import (
    WebhookNotifier,
    build_generic_payload,
    build_slack_payload,
    build_teams_payload,
)
from app.integrations import build_finding_event, dispatch_integrations


@pytest.fixture
def sample_finding() -> dict:
    return finding_payload(
        vulnerability_id=uuid.uuid4(),
        title="Log4j RCE",
        severity=Severity.CRITICAL,
        status=FindingStatus.CONFIRMED,
        asset_id=uuid.uuid4(),
        asset_name="app-prod",
        cve_id="CVE-2021-44228",
        cwe_id="CWE-502",
        cvss_score=10.0,
        description="JNDI injection",
        source_tool="nuclei",
    )


def test_severity_rank() -> None:
    assert severity_rank("critical") > severity_rank("high") > severity_rank("low")


def test_slack_and_teams_payloads(sample_finding: dict) -> None:
    slack = build_slack_payload(sample_finding)
    assert "blocks" in slack
    assert "CRITICAL" in slack["text"]
    teams = build_teams_payload(sample_finding)
    assert teams["@type"] == "MessageCard"
    assert teams["themeColor"] == "FF0000"
    generic = build_generic_payload(sample_finding)
    assert generic["event"] == "vulnerability.alert"


def test_webhook_skips_when_disabled(sample_finding: dict) -> None:
    notifier = WebhookNotifier(urls=["https://example.com/hook"], enabled=False)
    result = notifier.send(sample_finding)
    assert result[0]["skipped"] is True


def test_webhook_posts_with_shell_false_httpx(sample_finding: dict) -> None:
    notifier = WebhookNotifier(
        urls=["https://hooks.example.com/slack"],
        provider="slack",
        min_severity="high",
        enabled=True,
    )
    mock_resp = MagicMock(status_code=200)
    with patch("app.integrations.webhooks.httpx.Client") as client_cls:
        client = client_cls.return_value.__enter__.return_value
        client.post.return_value = mock_resp
        results = notifier.send(sample_finding)
    assert results[0]["ok"] is True
    client.post.assert_called_once()
    args, kwargs = client.post.call_args
    assert args[0].startswith("https://hooks.example.com/")
    assert "json" in kwargs


def test_cef_and_json_syslog_formats(sample_finding: dict) -> None:
    cef = to_cef(sample_finding)
    assert cef.startswith("CEF:0|NexuSec|NexuSec VA/PT|")
    assert "CVE-2021-44228" in cef or "cs1=" in cef
    line = to_json_syslog(sample_finding)
    data = json.loads(line)
    assert data["vulnerability"]["cve"] == "CVE-2021-44228"
    assert data["observer"]["product"] == "NexuSec"


def test_siem_forwarder_skipped_without_url(sample_finding: dict) -> None:
    fwd = SiemForwarder(enabled=True, url="", fmt="json")
    assert fwd.forward(sample_finding)["skipped"] is True


def test_siem_forwarder_posts_json(sample_finding: dict) -> None:
    fwd = SiemForwarder(
        enabled=True, url="https://siem.example.com/hec", fmt="json", hec_token="secret"
    )
    mock_resp = MagicMock(status_code=200)
    with patch("app.integrations.siem.httpx.Client") as client_cls:
        client = client_cls.return_value.__enter__.return_value
        client.post.return_value = mock_resp
        result = fwd.forward(sample_finding)
    assert result["ok"] is True
    headers = client.post.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Splunk secret"


def test_ticket_skips_non_critical(sample_finding: dict) -> None:
    sample_finding["severity"] = "high"
    result = sync_critical_ticket(sample_finding)
    assert result.action == "skipped"


def test_jira_create_issue(sample_finding: dict) -> None:
    client = JiraTicketClient()
    client.base_url = "https://jira.example.com"
    client.email = "bot@example.com"
    client.token = "token"
    client.project_key = "SEC"
    client.issue_type = "Bug"
    mock_resp = MagicMock(status_code=201)
    mock_resp.json.return_value = {"id": "10001", "key": "SEC-42"}
    with patch("app.integrations.ticketing.httpx.Client") as client_cls:
        http = client_cls.return_value.__enter__.return_value
        http.post.return_value = mock_resp
        result = client.create_or_update(sample_finding)
    assert result.action == "created"
    assert result.key == "SEC-42"
    assert "SEC-42" in (result.url or "")


def test_servicenow_create_incident(sample_finding: dict) -> None:
    client = ServiceNowTicketClient()
    client.base_url = "https://example.service-now.com"
    client.username = "bot"
    client.password = "pass"
    client.table = "incident"
    mock_resp = MagicMock(status_code=201)
    mock_resp.json.return_value = {
        "result": {"sys_id": "abc123", "number": "INC001"}
    }
    with patch("app.integrations.ticketing.httpx.Client") as client_cls:
        http = client_cls.return_value.__enter__.return_value
        http.post.return_value = mock_resp
        result = client.create_or_update(sample_finding)
    assert result.action == "created"
    assert result.key == "abc123"


def test_null_ticket_client() -> None:
    assert NullTicketClient().create_or_update({}).action == "skipped"


def test_dispatch_integrations_orchestration(sample_finding: dict) -> None:
    with patch("app.integrations.webhooks.WebhookNotifier.send", return_value=[{"ok": True}]):
        with patch(
            "app.integrations.ticketing.sync_critical_ticket"
        ) as ticket_fn:
            ticket_fn.return_value = MagicMock(
                provider="jira",
                action="created",
                key="SEC-1",
                url="https://jira/browse/SEC-1",
                error=None,
            )
            # sync_critical_ticket returns TicketResult — patch at orchestrator import path
            pass

    with patch("app.integrations.webhooks.WebhookNotifier.send", return_value=[{"ok": True}]):
        with patch(
            "app.integrations.ticketing.sync_critical_ticket",
            return_value=MagicMock(
                provider="jira",
                action="created",
                key="SEC-1",
                url="https://jira/browse/SEC-1",
                error=None,
            ),
        ):
            with patch(
                "app.integrations.siem.SiemForwarder.forward",
                return_value={"ok": True},
            ):
                # dispatch_integrations imports symbols at module level — patch where used
                with patch(
                    "app.integrations.dispatch_integrations", wraps=dispatch_integrations
                ):
                    from app.integrations import dispatch_integrations as di
                    with patch("app.integrations.webhooks.WebhookNotifier") as wn:
                        wn.return_value.send.return_value = [{"ok": True}]
                        with patch(
                            "app.integrations.ticketing.sync_critical_ticket"
                        ) as st:
                            st.return_value = MagicMock(
                                provider="jira",
                                action="created",
                                key="SEC-1",
                                url="u",
                                error=None,
                            )
                            # Actually dispatch_integrations imports sync_critical_ticket at load
                            # Patch app.integrations module attributes
                            import app.integrations as integ

                            with patch.object(
                                integ,
                                "WebhookNotifier",
                                wn,
                            ):
                                pass

    # Cleaner direct test of dispatch_integrations internals via patching its dependencies
    import app.integrations as integ_mod

    with patch.object(integ_mod, "WebhookNotifier") as WN:
        WN.return_value.send.return_value = [{"ok": True}]
        with patch.object(integ_mod, "sync_critical_ticket") as ST:
            ST.return_value = MagicMock(
                provider="jira", action="created", key="SEC-1", url="u", error=None
            )
            with patch.object(integ_mod, "SiemForwarder") as SF:
                SF.return_value.forward.return_value = {"ok": True, "format": "json"}
                out = integ_mod.dispatch_integrations(sample_finding)
    assert out["webhook"][0]["ok"] is True
    assert out["ticket"]["key"] == "SEC-1"
    assert out["siem"]["ok"] is True


def test_build_finding_event() -> None:
    event = build_finding_event(
        vulnerability_id=uuid.uuid4(),
        title="x",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        asset_id=uuid.uuid4(),
        asset_name="a",
    )
    assert event["product"] == "NexuSec"
    assert event["severity"] == "high"
