"""Tests for configuration parsing."""

import pytest
from src.config import Settings


class TestExpectedPortsList:
    """Tests for expected_ports_list property."""

    def test_expected_ports_list_parsing(self):
        """Test parsing valid port formats with protocol."""
        settings = Settings(expected_ports="80/tcp,443/tcp,22/tcp")
        result = settings.expected_ports_list

        assert len(result) == 3
        assert result[0] == {"port": 80, "protocol": "tcp"}
        assert result[1] == {"port": 443, "protocol": "tcp"}
        assert result[2] == {"port": 22, "protocol": "tcp"}

    def test_expected_ports_list_with_default_protocol(self):
        """Test that ports without protocol default to tcp."""
        settings = Settings(expected_ports="80,443")
        result = settings.expected_ports_list

        assert len(result) == 2
        assert result[0] == {"port": 80, "protocol": "tcp"}
        assert result[1] == {"port": 443, "protocol": "tcp"}

    def test_expected_ports_list_empty(self):
        """Test empty/None expected_ports returns empty list."""
        settings = Settings(expected_ports=None)
        assert settings.expected_ports_list == []

        settings = Settings(expected_ports="")
        assert settings.expected_ports_list == []

    def test_expected_ports_list_with_udp(self):
        """Test parsing UDP ports."""
        settings = Settings(expected_ports="53/udp,123/udp")
        result = settings.expected_ports_list

        assert len(result) == 2
        assert result[0] == {"port": 53, "protocol": "udp"}
        assert result[1] == {"port": 123, "protocol": "udp"}


class TestSmtpConfigured:
    """Tests for smtp_configured property."""

    def test_smtp_configured_all_set(self):
        """Test returns True when all SMTP fields are set."""
        settings = Settings(
            smtp_host="smtp.example.com",
            smtp_user="user@example.com",
            smtp_password="secret",
            smtp_from="sender@example.com",
            smtp_to="recipient@example.com",
        )
        assert settings.smtp_configured is True

    def test_smtp_configured_missing_field(self):
        """Test returns False when any SMTP field is missing."""
        # Missing host
        settings = Settings(
            smtp_host=None,
            smtp_user="user@example.com",
            smtp_password="secret",
            smtp_from="sender@example.com",
            smtp_to="recipient@example.com",
        )
        assert settings.smtp_configured is False

        # Missing password
        settings = Settings(
            smtp_host="smtp.example.com",
            smtp_user="user@example.com",
            smtp_password=None,
            smtp_from="sender@example.com",
            smtp_to="recipient@example.com",
        )
        assert settings.smtp_configured is False


class TestWebhookConfigured:
    """Tests for webhook_configured property."""

    def test_webhook_configured_with_url(self):
        """Test returns True when webhook URL is set."""
        settings = Settings(webhook_url="https://hooks.slack.com/services/xxx")
        assert settings.webhook_configured is True

    def test_webhook_configured_without_url(self):
        """Test returns False when webhook URL is not set."""
        settings = Settings(webhook_url=None)
        assert settings.webhook_configured is False

        settings = Settings(webhook_url="")
        assert settings.webhook_configured is False
