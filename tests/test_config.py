"""Tests for configuration parsing."""

from datetime import datetime, timezone

import pytest

from src import config as config_module
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


class TestWireGuardProbePorts:
    """Tests for WireGuard probe ports parsing."""

    def test_wireguard_probe_ports_default(self):
        """Returns empty list when not configured - ports must be explicitly set."""
        settings = Settings(wireguard_probe_ports=None)
        assert settings.wireguard_probe_ports_list == []

    def test_wireguard_probe_ports_parsing(self):
        """Parses configured ports list."""
        settings = Settings(wireguard_probe_ports="51820, 12345")
        assert settings.wireguard_probe_ports_list == [51820, 12345]


class TestTargetHostValidation:
    """Tests for TARGET_HOST validation rules."""

    def test_rejects_shell_metacharacters(self):
        settings = Settings(target_host="example.com")
        assert settings.target_host == "example.com"

        with pytest.raises(ValueError):
            Settings(target_host="example.com;rm -rf /")

    def test_allows_ipv4(self):
        settings = Settings(target_host="192.168.1.10")
        assert settings.target_host == "192.168.1.10"


class TestTimezoneAndLocalIso:
    """Tests for timezone handling utilities."""

    def test_tz_falls_back_to_utc(self):
        settings = Settings(display_timezone="Not/AZone", wireguard_probe_ports=None)
        assert str(settings.tz) in {"UTC", "UTC+00:00"}

    def test_to_local_iso_handles_none_and_naive(self, monkeypatch):
        monkeypatch.setattr(config_module, "settings", Settings(display_timezone="UTC", wireguard_probe_ports=None))

        assert config_module.to_local_iso(None) is None

        naive = datetime(2025, 1, 1, 0, 0, 0)
        iso = config_module.to_local_iso(naive)
        assert iso.startswith("2025-01-01T00:00:00")

        aware = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        iso2 = config_module.to_local_iso(aware)
        assert iso2.startswith("2025-01-01T00:00:00")
