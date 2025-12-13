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
