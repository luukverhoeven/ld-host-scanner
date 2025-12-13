"""Tests for the common port service lookup module."""

import pytest

from src.scanner.services import (
    COMMON_PORTS,
    get_common_service,
    get_common_service_name,
    enrich_port_with_common_service,
    enrich_ports_list,
    format_service_display,
)


class TestCommonPorts:
    """Tests for the COMMON_PORTS database."""

    def test_common_ports_not_empty(self):
        """Verify the port database has entries."""
        assert len(COMMON_PORTS) > 50  # Should have at least 50+ common ports

    def test_common_ports_structure(self):
        """Verify entries have correct structure."""
        for key, value in COMMON_PORTS.items():
            assert isinstance(key, tuple)
            assert len(key) == 2
            assert isinstance(key[0], int)  # Port number
            assert isinstance(key[1], str)  # Protocol
            assert key[1] in ("tcp", "udp")
            assert "service" in value
            assert "description" in value


class TestGetCommonService:
    """Tests for get_common_service function."""

    def test_known_tcp_port(self):
        """Test lookup for well-known TCP port."""
        result = get_common_service(22, "tcp")
        assert result is not None
        assert result["service"] == "ssh"
        assert "description" in result

    def test_known_udp_port(self):
        """Test lookup for well-known UDP port."""
        result = get_common_service(53, "udp")
        assert result is not None
        assert result["service"] == "dns"

    def test_http_port(self):
        """Test lookup for HTTP port."""
        result = get_common_service(80, "tcp")
        assert result is not None
        assert result["service"] == "http"

    def test_https_port(self):
        """Test lookup for HTTPS port."""
        result = get_common_service(443, "tcp")
        assert result is not None
        assert result["service"] == "https"

    def test_unknown_port(self):
        """Test lookup for unknown port."""
        result = get_common_service(54321, "tcp")
        assert result is None

    def test_protocol_case_insensitive(self):
        """Test that protocol lookup is case-insensitive."""
        result_lower = get_common_service(22, "tcp")
        result_upper = get_common_service(22, "TCP")
        assert result_lower == result_upper


class TestGetCommonServiceName:
    """Tests for get_common_service_name function."""

    def test_returns_service_name_only(self):
        """Test that only service name is returned."""
        result = get_common_service_name(22, "tcp")
        assert result == "ssh"

    def test_returns_none_for_unknown(self):
        """Test that None is returned for unknown port."""
        result = get_common_service_name(54321, "tcp")
        assert result is None


class TestEnrichPortWithCommonService:
    """Tests for enrich_port_with_common_service function."""

    def test_enriches_known_port(self):
        """Test that known port gets common_service added."""
        port_data = {"port": 443, "protocol": "tcp", "service": "https"}
        result = enrich_port_with_common_service(port_data)
        assert result["common_service"] == "https"

    def test_enriches_unknown_port(self):
        """Test that unknown port gets None common_service."""
        port_data = {"port": 54321, "protocol": "tcp", "service": "unknown"}
        result = enrich_port_with_common_service(port_data)
        assert result["common_service"] is None

    def test_preserves_original_data(self):
        """Test that original port data is preserved."""
        port_data = {"port": 22, "protocol": "tcp", "service": "openssh", "version": "7.4"}
        result = enrich_port_with_common_service(port_data)
        assert result["port"] == 22
        assert result["protocol"] == "tcp"
        assert result["service"] == "openssh"
        assert result["version"] == "7.4"
        assert result["common_service"] == "ssh"


class TestEnrichPortsList:
    """Tests for enrich_ports_list function."""

    def test_enriches_multiple_ports(self):
        """Test enrichment of a list of ports."""
        ports = [
            {"port": 22, "protocol": "tcp", "service": "ssh"},
            {"port": 80, "protocol": "tcp", "service": "http"},
            {"port": 54321, "protocol": "tcp", "service": "unknown"},
        ]
        result = enrich_ports_list(ports)

        assert len(result) == 3
        assert result[0]["common_service"] == "ssh"
        assert result[1]["common_service"] == "http"
        assert result[2]["common_service"] is None

    def test_empty_list(self):
        """Test enrichment of empty list."""
        result = enrich_ports_list([])
        assert result == []


class TestFormatServiceDisplay:
    """Tests for format_service_display function."""

    def test_detected_same_as_common(self):
        """Test when detected service matches common service."""
        # Should not repeat: just return the service name
        result = format_service_display("ssh", 22, "tcp")
        assert result == "ssh"

    def test_detected_different_from_common(self):
        """Test when detected service differs from common."""
        # Should show: detected (common)
        result = format_service_display("nginx/1.20.1", 80, "tcp")
        assert result == "nginx/1.20.1 (http)"

    def test_unknown_with_common(self):
        """Test unknown detected service with known common service."""
        result = format_service_display("unknown", 443, "tcp")
        assert result == "unknown (https)"

    def test_unknown_without_common(self):
        """Test unknown service with no common mapping."""
        result = format_service_display("unknown", 54321, "tcp")
        assert result == "unknown"

    def test_none_detected_with_common(self):
        """Test None detected service with known common service."""
        result = format_service_display(None, 22, "tcp")
        assert result == "unknown (ssh)"

    def test_detected_no_common(self):
        """Test detected service with no common mapping."""
        result = format_service_display("custom-app", 54321, "tcp")
        assert result == "custom-app"


class TestSpecificPorts:
    """Tests for specific commonly used ports."""

    @pytest.mark.parametrize("port,protocol,expected", [
        (22, "tcp", "ssh"),
        (80, "tcp", "http"),
        (443, "tcp", "https"),
        (3306, "tcp", "mysql"),
        (5432, "tcp", "postgresql"),
        (6379, "tcp", "redis"),
        (27017, "tcp", "mongodb"),
        (3389, "tcp", "rdp"),
        (51820, "udp", "wireguard"),
        (53, "udp", "dns"),
    ])
    def test_common_ports(self, port, protocol, expected):
        """Test various common ports return expected service names."""
        result = get_common_service_name(port, protocol)
        assert result == expected
