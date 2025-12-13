"""Tests for notification modules (email/webhook/orchestrator)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_email_alert_skipped_when_not_configured(monkeypatch):
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(smtp_configured=False))
    result = await email_notifier.send_email_alert(
        scan_id="scan",
        target="example.com",
        ports=[],
        changes=[],
        host_status="up",
    )
    assert result is False


@pytest.mark.asyncio
async def test_email_alert_sends_and_saves_notification(monkeypatch):
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=True,
        smtp_from="from@example.com",
        smtp_to="to@example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
    ))

    with patch.object(email_notifier, "save_notification", new=AsyncMock()) as save_mock, \
         patch.object(email_notifier.aiosmtplib, "send", new=AsyncMock()) as send_mock:
        result = await email_notifier.send_email_alert(
            scan_id="scan-1",
            target="example.com",
            ports=[{"port": 80, "protocol": "tcp", "service": "http", "version": ""}],
            changes=[],
            host_status="up",
        )

    assert result is True
    assert send_mock.await_count == 1
    save_mock.assert_awaited()


@pytest.mark.asyncio
async def test_email_alert_failure_records_failed_notification(monkeypatch):
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=True,
        smtp_from="from@example.com",
        smtp_to="to@example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
    ))

    with patch.object(email_notifier, "save_notification", new=AsyncMock()) as save_mock, \
         patch.object(email_notifier.aiosmtplib, "send", new=AsyncMock(side_effect=RuntimeError("boom"))):
        result = await email_notifier.send_email_alert(
            scan_id="scan-1",
            target="example.com",
            ports=[],
            changes=[],
            host_status="down",
        )

    assert result is False
    save_mock.assert_awaited()
    kwargs = save_mock.await_args.kwargs
    assert kwargs["status"] == "failed"


@pytest.mark.asyncio
async def test_missing_ports_email_sends_when_configured(monkeypatch):
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=True,
        smtp_from="from@example.com",
        smtp_to="to@example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
    ))

    with patch.object(email_notifier, "save_notification", new=AsyncMock()) as save_mock, \
         patch.object(email_notifier.aiosmtplib, "send", new=AsyncMock()):
        ok = await email_notifier.send_missing_ports_email(
            "example.com",
            [{"port": 51820, "protocol": "udp"}],
        )

    assert ok is True
    save_mock.assert_awaited()


def test_webhook_payload_type_detection():
    from src.notifications.webhook_notifier import _is_slack_webhook

    assert _is_slack_webhook("https://hooks.slack.com/services/abc") is True
    assert _is_slack_webhook("https://discord.com/api/webhooks/abc") is False


@pytest.mark.asyncio
async def test_webhook_skipped_when_not_configured(monkeypatch):
    from src.notifications import webhook_notifier

    monkeypatch.setattr(webhook_notifier, "settings", SimpleNamespace(webhook_configured=False))
    result = await webhook_notifier.send_webhook_alert(
        scan_id="scan",
        target="example.com",
        ports=[],
        changes=[],
        host_status="up",
    )
    assert result is False


@pytest.mark.asyncio
async def test_webhook_success_saves_notification(monkeypatch):
    from src.notifications import webhook_notifier

    monkeypatch.setattr(webhook_notifier, "settings", SimpleNamespace(
        webhook_configured=True,
        webhook_url="https://discord.com/api/webhooks/abc",
    ))

    response = MagicMock()
    response.raise_for_status.return_value = None

    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = AsyncMock(return_value=response)

    with patch.object(webhook_notifier.httpx, "AsyncClient", return_value=client), \
         patch.object(webhook_notifier, "save_notification", new=AsyncMock()) as save_mock:
        ok = await webhook_notifier.send_webhook_alert(
            scan_id="scan-1",
            target="example.com",
            ports=[],
            changes=[],
            host_status="up",
        )

    assert ok is True
    save_mock.assert_awaited()


@pytest.mark.asyncio
async def test_host_offline_webhook_sends_discord_payload(monkeypatch):
    from src.notifications import webhook_notifier

    monkeypatch.setattr(webhook_notifier, "settings", SimpleNamespace(
        webhook_configured=True,
        webhook_url="https://discord.com/api/webhooks/abc",
    ))

    response = MagicMock()
    response.raise_for_status.return_value = None

    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = AsyncMock(return_value=response)

    with patch.object(webhook_notifier.httpx, "AsyncClient", return_value=client), \
         patch.object(webhook_notifier, "save_notification", new=AsyncMock()) as save_mock:
        ok = await webhook_notifier.send_host_offline_webhook("example.com")

    assert ok is True
    save_mock.assert_awaited()


@pytest.mark.asyncio
async def test_notifier_orchestrator_updates_metrics_and_calls_channels(monkeypatch):
    from src.notifications import notifier

    with patch.object(notifier, "send_email_alert", new=AsyncMock(return_value=True)) as email_mock, \
         patch.object(notifier, "send_webhook_alert", new=AsyncMock(return_value=False)) as webhook_mock:
        sent = MagicMock()
        failed = MagicMock()
        sent.labels.return_value.inc = MagicMock()
        failed.labels.return_value.inc = MagicMock()
        monkeypatch.setattr(notifier, "notifications_sent_total", sent)
        monkeypatch.setattr(notifier, "notifications_failed_total", failed)

        await notifier.send_notifications(
            scan_id="scan-1",
            target="example.com",
            ports=[],
            changes=[{"port": 80, "protocol": "tcp", "change_type": "opened"}],
            host_status="up",
        )

    email_mock.assert_awaited()
    webhook_mock.assert_awaited()
    assert sent.labels.return_value.inc.call_count == 1
    assert failed.labels.return_value.inc.call_count == 1


@pytest.mark.asyncio
async def test_notifier_missing_ports_updates_metrics(monkeypatch):
    from src.notifications import notifier

    sent = MagicMock()
    failed = MagicMock()
    sent.labels.return_value.inc = MagicMock()
    failed.labels.return_value.inc = MagicMock()
    monkeypatch.setattr(notifier, "notifications_sent_total", sent)
    monkeypatch.setattr(notifier, "notifications_failed_total", failed)

    with patch.object(notifier, "send_missing_ports_email", new=AsyncMock(return_value=True)), \
         patch.object(notifier, "send_missing_ports_webhook", new=AsyncMock(return_value=False)):
        await notifier.send_missing_ports_notification(
            "example.com",
            [{"port": 80, "protocol": "tcp"}],
        )

    assert sent.labels.return_value.inc.call_count == 1
    assert failed.labels.return_value.inc.call_count == 1


@pytest.mark.asyncio
async def test_notifier_host_offline_updates_metrics(monkeypatch):
    from src.notifications import notifier

    sent = MagicMock()
    failed = MagicMock()
    sent.labels.return_value.inc = MagicMock()
    failed.labels.return_value.inc = MagicMock()
    monkeypatch.setattr(notifier, "notifications_sent_total", sent)
    monkeypatch.setattr(notifier, "notifications_failed_total", failed)

    with patch.object(notifier, "send_host_offline_email", new=AsyncMock(return_value=True)), \
         patch.object(notifier, "send_host_offline_webhook", new=AsyncMock(return_value=True)):
        await notifier.send_host_status_notification("example.com", "offline")

    assert sent.labels.return_value.inc.call_count == 2


class TestDiscordEmbedBuilder:
    """Tests for Discord embed payload building."""

    def test_build_discord_embed_with_changes(self):
        """Test Discord embed with port changes."""
        from src.notifications.webhook_notifier import _build_discord_embed

        ports = [{"port": 80, "protocol": "tcp", "service": "http"}]
        changes = [{"port": 443, "protocol": "tcp", "change_type": "opened"}]

        payload = _build_discord_embed("scan-1", "example.com", ports, changes, "up")

        assert "embeds" in payload
        assert len(payload["embeds"]) == 1
        embed = payload["embeds"][0]
        assert embed["title"] == "Security Scan Alert"
        assert embed["color"] == 16711680  # Red for changes
        assert "fields" in embed

    def test_build_discord_embed_no_changes(self):
        """Test Discord embed without changes (orange color)."""
        from src.notifications.webhook_notifier import _build_discord_embed

        ports = [{"port": 80, "protocol": "tcp", "service": "http"}]
        changes = []

        payload = _build_discord_embed("scan-1", "example.com", ports, changes, "up")

        embed = payload["embeds"][0]
        assert embed["color"] == 16744192  # Orange for ports without changes

    def test_build_discord_embed_clean_scan(self):
        """Test Discord embed with no ports (green color)."""
        from src.notifications.webhook_notifier import _build_discord_embed

        ports = []
        changes = []

        payload = _build_discord_embed("scan-1", "example.com", ports, changes, "up")

        embed = payload["embeds"][0]
        assert embed["color"] == 65280  # Green for clean

    def test_build_discord_embed_port_list_limited(self):
        """Test Discord embed limits port list to 15."""
        from src.notifications.webhook_notifier import _build_discord_embed

        ports = [{"port": i, "protocol": "tcp", "service": f"svc{i}"} for i in range(1, 20)]
        changes = []

        payload = _build_discord_embed("scan-1", "example.com", ports, changes, "up")

        # Should not include port list field when > 15 ports
        embed = payload["embeds"][0]
        field_names = [f["name"] for f in embed["fields"]]
        assert "Detected Ports" not in field_names

    def test_build_discord_embed_includes_footer(self):
        """Test Discord embed includes scan ID in footer."""
        from src.notifications.webhook_notifier import _build_discord_embed

        payload = _build_discord_embed("test-scan-123", "example.com", [], [], "up")

        embed = payload["embeds"][0]
        assert embed["footer"]["text"] == "Scan ID: test-scan-123"


class TestSlackPayloadBuilder:
    """Tests for Slack payload building."""

    def test_build_slack_payload_with_changes(self):
        """Test Slack payload with port changes."""
        from src.notifications.webhook_notifier import _build_slack_payload

        ports = [{"port": 80, "protocol": "tcp", "service": "http"}]
        changes = [{"port": 443, "protocol": "tcp", "change_type": "opened"}]

        payload = _build_slack_payload("scan-1", "example.com", ports, changes, "up")

        assert "attachments" in payload
        assert len(payload["attachments"]) == 1
        attachment = payload["attachments"][0]
        assert attachment["color"] == "#FF0000"  # Red for changes
        assert attachment["title"] == "Security Scan: example.com"

    def test_build_slack_payload_no_changes(self):
        """Test Slack payload without changes (orange color)."""
        from src.notifications.webhook_notifier import _build_slack_payload

        ports = [{"port": 80, "protocol": "tcp", "service": "http"}]
        changes = []

        payload = _build_slack_payload("scan-1", "example.com", ports, changes, "up")

        attachment = payload["attachments"][0]
        assert attachment["color"] == "#FFA500"  # Orange

    def test_build_slack_payload_clean_scan(self):
        """Test Slack payload with no ports (green color)."""
        from src.notifications.webhook_notifier import _build_slack_payload

        payload = _build_slack_payload("scan-1", "example.com", [], [], "up")

        attachment = payload["attachments"][0]
        assert attachment["color"] == "#00FF00"  # Green

    def test_build_slack_payload_port_list_limited(self):
        """Test Slack payload limits port list to 10."""
        from src.notifications.webhook_notifier import _build_slack_payload

        ports = [{"port": i, "protocol": "tcp", "service": f"svc{i}"} for i in range(1, 15)]
        changes = []

        payload = _build_slack_payload("scan-1", "example.com", ports, changes, "up")

        # Should not include port list when > 10 ports
        attachment = payload["attachments"][0]
        field_titles = [f["title"] for f in attachment["fields"]]
        assert "Detected Ports" not in field_titles


class TestSlackWebhookDetection:
    """Tests for Slack webhook URL detection."""

    def test_detect_slack_webhook_hooks_slack(self):
        """Test detection of hooks.slack.com webhook."""
        from src.notifications.webhook_notifier import _is_slack_webhook

        assert _is_slack_webhook("https://hooks.slack.com/services/abc/def") is True

    def test_detect_slack_webhook_slack_com(self):
        """Test detection of slack.com webhook."""
        from src.notifications.webhook_notifier import _is_slack_webhook

        assert _is_slack_webhook("https://api.slack.com/webhook/123") is True

    def test_detect_discord_webhook(self):
        """Test Discord webhook is not detected as Slack."""
        from src.notifications.webhook_notifier import _is_slack_webhook

        assert _is_slack_webhook("https://discord.com/api/webhooks/abc") is False

    def test_detect_generic_webhook(self):
        """Test generic webhook is not detected as Slack."""
        from src.notifications.webhook_notifier import _is_slack_webhook

        assert _is_slack_webhook("https://example.com/webhook") is False


@pytest.mark.asyncio
async def test_missing_ports_webhook_sends_discord(monkeypatch):
    """Test missing ports webhook sends Discord payload."""
    from src.notifications import webhook_notifier

    monkeypatch.setattr(webhook_notifier, "settings", SimpleNamespace(
        webhook_configured=True,
        webhook_url="https://discord.com/api/webhooks/abc",
    ))

    response = MagicMock()
    response.raise_for_status.return_value = None

    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = AsyncMock(return_value=response)

    with patch.object(webhook_notifier.httpx, "AsyncClient", return_value=client), \
         patch.object(webhook_notifier, "save_notification", new=AsyncMock()) as save_mock:
        ok = await webhook_notifier.send_missing_ports_webhook(
            "example.com",
            [{"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}]
        )

    assert ok is True
    save_mock.assert_awaited()
    # Verify the POST was called with Discord-formatted payload (embeds)
    call_args = client.post.call_args
    assert "embeds" in call_args.kwargs.get("json", call_args.args[1] if len(call_args.args) > 1 else {})


@pytest.mark.asyncio
async def test_missing_ports_webhook_skipped_when_not_configured(monkeypatch):
    """Test missing ports webhook is skipped when not configured."""
    from src.notifications import webhook_notifier

    monkeypatch.setattr(webhook_notifier, "settings", SimpleNamespace(
        webhook_configured=False,
    ))

    result = await webhook_notifier.send_missing_ports_webhook(
        "example.com",
        [{"port": 80, "protocol": "tcp"}]
    )

    assert result is False


@pytest.mark.asyncio
async def test_host_offline_webhook_skipped_when_not_configured(monkeypatch):
    """Test host offline webhook is skipped when not configured."""
    from src.notifications import webhook_notifier

    monkeypatch.setattr(webhook_notifier, "settings", SimpleNamespace(
        webhook_configured=False,
    ))

    result = await webhook_notifier.send_host_offline_webhook("example.com")

    assert result is False


@pytest.mark.asyncio
async def test_webhook_http_error_saves_failed_notification(monkeypatch):
    """Test webhook HTTP error saves failed notification."""
    from src.notifications import webhook_notifier
    import httpx

    monkeypatch.setattr(webhook_notifier, "settings", SimpleNamespace(
        webhook_configured=True,
        webhook_url="https://discord.com/api/webhooks/abc",
    ))

    response = MagicMock()
    response.status_code = 429
    response.text = "Rate limited"
    error = httpx.HTTPStatusError("Rate limited", request=MagicMock(), response=response)

    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = AsyncMock(side_effect=error)

    with patch.object(webhook_notifier.httpx, "AsyncClient", return_value=client), \
         patch.object(webhook_notifier, "save_notification", new=AsyncMock()) as save_mock:
        ok = await webhook_notifier.send_webhook_alert(
            scan_id="scan-1",
            target="example.com",
            ports=[],
            changes=[],
            host_status="up",
        )

    assert ok is False
    save_mock.assert_awaited()
    kwargs = save_mock.await_args.kwargs
    assert kwargs["status"] == "failed"


@pytest.mark.asyncio
async def test_webhook_generic_error_saves_failed_notification(monkeypatch):
    """Test webhook generic error saves failed notification."""
    from src.notifications import webhook_notifier

    monkeypatch.setattr(webhook_notifier, "settings", SimpleNamespace(
        webhook_configured=True,
        webhook_url="https://discord.com/api/webhooks/abc",
    ))

    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = AsyncMock(side_effect=ConnectionError("Network error"))

    with patch.object(webhook_notifier.httpx, "AsyncClient", return_value=client), \
         patch.object(webhook_notifier, "save_notification", new=AsyncMock()) as save_mock:
        ok = await webhook_notifier.send_webhook_alert(
            scan_id="scan-1",
            target="example.com",
            ports=[],
            changes=[],
            host_status="up",
        )

    assert ok is False
    save_mock.assert_awaited()
    kwargs = save_mock.await_args.kwargs
    assert kwargs["status"] == "failed"


# Email Notifier Tests

class TestBuildPortTable:
    """Tests for _build_port_table function."""

    def test_build_port_table_with_ports(self):
        """Test building HTML table with ports."""
        from src.notifications.email_notifier import _build_port_table

        ports = [
            {"port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.18"},
            {"port": 443, "protocol": "tcp", "service": "https", "version": ""},
        ]

        result = _build_port_table(ports)

        assert "<table" in result
        assert "80" in result
        assert "TCP" in result
        assert "http" in result
        assert "nginx 1.18" in result

    def test_build_port_table_empty(self):
        """Test building table with no ports."""
        from src.notifications.email_notifier import _build_port_table

        result = _build_port_table([])

        assert "No open ports detected" in result
        assert "<table" not in result

    def test_build_port_table_escapes_html(self):
        """Test that port table escapes HTML characters."""
        from src.notifications.email_notifier import _build_port_table

        ports = [
            {"port": 80, "protocol": "tcp", "service": "<script>alert(1)</script>", "version": ""},
        ]

        result = _build_port_table(ports)

        assert "<script>" not in result
        assert "&lt;script&gt;" in result


class TestBuildChangesList:
    """Tests for _build_changes_list function."""

    def test_build_changes_list_with_changes(self):
        """Test building HTML list with port changes."""
        from src.notifications.email_notifier import _build_changes_list

        changes = [
            {"port": 443, "protocol": "tcp", "change_type": "opened", "service": "https"},
            {"port": 22, "protocol": "tcp", "change_type": "closed", "service": "ssh"},
        ]

        result = _build_changes_list(changes)

        assert "Port Changes Detected" in result
        assert "OPENED" in result
        assert "CLOSED" in result
        assert "443" in result
        assert "22" in result

    def test_build_changes_list_empty(self):
        """Test building list with no changes."""
        from src.notifications.email_notifier import _build_changes_list

        result = _build_changes_list([])

        assert result == ""


@pytest.mark.asyncio
async def test_send_host_offline_email_success(monkeypatch):
    """Test sending host offline email successfully."""
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
        smtp_from="from@example.com",
        smtp_to="to@example.com",
    ))

    with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send, \
         patch.object(email_notifier, "save_notification", new=AsyncMock()) as mock_save:

        result = await email_notifier.send_host_offline_email("example.com")

    assert result is True
    mock_send.assert_awaited_once()
    mock_save.assert_awaited()
    assert mock_save.await_args.kwargs["status"] == "sent"


@pytest.mark.asyncio
async def test_send_host_offline_email_failure(monkeypatch):
    """Test host offline email failure handling."""
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
        smtp_from="from@example.com",
        smtp_to="to@example.com",
    ))

    with patch("aiosmtplib.send", new_callable=AsyncMock, side_effect=Exception("SMTP error")), \
         patch.object(email_notifier, "save_notification", new=AsyncMock()) as mock_save:

        result = await email_notifier.send_host_offline_email("example.com")

    assert result is False
    mock_save.assert_awaited()
    assert mock_save.await_args.kwargs["status"] == "failed"


@pytest.mark.asyncio
async def test_send_host_offline_email_not_configured(monkeypatch):
    """Test host offline email skipped when not configured."""
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=False,
    ))

    result = await email_notifier.send_host_offline_email("example.com")

    assert result is False


@pytest.mark.asyncio
async def test_send_missing_ports_email_success(monkeypatch):
    """Test sending missing ports email successfully."""
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
        smtp_from="from@example.com",
        smtp_to="to@example.com",
    ))

    missing_ports = [
        {"port": 80, "protocol": "tcp"},
        {"port": 443, "protocol": "tcp"},
    ]

    with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send, \
         patch.object(email_notifier, "save_notification", new=AsyncMock()) as mock_save:

        result = await email_notifier.send_missing_ports_email("example.com", missing_ports)

    assert result is True
    mock_send.assert_awaited_once()
    # Check that the email message contains the ports
    call_args = mock_send.call_args
    message = call_args.args[0]
    assert "80" in str(message)


@pytest.mark.asyncio
async def test_send_missing_ports_email_failure(monkeypatch):
    """Test missing ports email failure handling."""
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
        smtp_from="from@example.com",
        smtp_to="to@example.com",
    ))

    with patch("aiosmtplib.send", new_callable=AsyncMock, side_effect=Exception("SMTP error")), \
         patch.object(email_notifier, "save_notification", new=AsyncMock()) as mock_save:

        result = await email_notifier.send_missing_ports_email("example.com", [{"port": 80, "protocol": "tcp"}])

    assert result is False
    mock_save.assert_awaited()
    assert mock_save.await_args.kwargs["status"] == "failed"


@pytest.mark.asyncio
async def test_send_email_alert_with_changes(monkeypatch):
    """Test sending email alert with port changes."""
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
        smtp_from="from@example.com",
        smtp_to="to@example.com",
    ))

    ports = [{"port": 80, "protocol": "tcp", "service": "http", "version": ""}]
    changes = [{"port": 443, "protocol": "tcp", "change_type": "opened", "service": "https"}]

    with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send, \
         patch.object(email_notifier, "save_notification", new=AsyncMock()):

        result = await email_notifier.send_email_alert(
            scan_id="scan-1",
            target="example.com",
            ports=ports,
            changes=changes,
            host_status="up",
        )

    assert result is True
    call_args = mock_send.call_args
    message = call_args.args[0]
    # Check subject includes changes count
    assert "1 changes detected" in message["Subject"]


@pytest.mark.asyncio
async def test_send_email_alert_no_changes(monkeypatch):
    """Test sending email alert without changes."""
    from src.notifications import email_notifier

    monkeypatch.setattr(email_notifier, "settings", SimpleNamespace(
        smtp_configured=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
        smtp_from="from@example.com",
        smtp_to="to@example.com",
    ))

    ports = [
        {"port": 80, "protocol": "tcp", "service": "http", "version": ""},
        {"port": 443, "protocol": "tcp", "service": "https", "version": ""},
    ]

    with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send, \
         patch.object(email_notifier, "save_notification", new=AsyncMock()):

        result = await email_notifier.send_email_alert(
            scan_id="scan-1",
            target="example.com",
            ports=ports,
            changes=[],
            host_status="up",
        )

    assert result is True
    call_args = mock_send.call_args
    message = call_args.args[0]
    # Check subject includes port count
    assert "2 open ports" in message["Subject"]
