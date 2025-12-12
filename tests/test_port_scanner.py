"""Tests for port scanner functions."""

import pytest
from unittest.mock import patch, MagicMock


class TestParseRustscanOutput:
    """Tests for _parse_rustscan_output method."""

    def test_parse_rustscan_output_with_ports(self):
        """Test parsing output with multiple ports."""
        # Mock nmap.PortScanner to avoid requiring nmap binary
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
        output = "example.com -> [80, 443, 8080]"

        result = scanner._parse_rustscan_output("example.com", output)

        assert result["host_status"] == "up"
        assert len(result["ports"]) == 3
        assert result["ports"][0] == {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "unknown",
            "version": "",
        }
        assert result["ports"][1]["port"] == 443
        assert result["ports"][2]["port"] == 8080

    def test_parse_rustscan_output_single_port(self):
        """Test parsing output with a single port."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
        output = "example.com -> [443]"

        result = scanner._parse_rustscan_output("example.com", output)

        assert result["host_status"] == "up"
        assert len(result["ports"]) == 1
        assert result["ports"][0]["port"] == 443

    def test_parse_rustscan_output_empty(self):
        """Test parsing empty output returns down status."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

        result = scanner._parse_rustscan_output("example.com", "")
        assert result["host_status"] == "down"
        assert result["ports"] == []

        result = scanner._parse_rustscan_output("example.com", None)
        assert result["host_status"] == "down"
        assert result["ports"] == []

    def test_parse_rustscan_output_no_arrow(self):
        """Test parsing output without arrow returns down status."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
        output = "Some random output without ports"

        result = scanner._parse_rustscan_output("example.com", output)

        assert result["host_status"] == "down"
        assert result["ports"] == []

    def test_parse_rustscan_output_empty_brackets(self):
        """Test parsing output with empty brackets."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
        output = "example.com -> []"

        result = scanner._parse_rustscan_output("example.com", output)

        assert result["host_status"] == "up"
        assert result["ports"] == []


class TestCheckExpectedPorts:
    """Tests for check_expected_ports function."""

    def test_check_expected_ports_all_present(self):
        """Test when all expected ports are found."""
        all_ports = [
            {"port": 80, "protocol": "tcp", "state": "open"},
            {"port": 443, "protocol": "tcp", "state": "open"},
            {"port": 22, "protocol": "tcp", "state": "open"},
        ]
        expected = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]

        missing = check_expected_ports(all_ports, expected)

        assert missing == []

    def test_check_expected_ports_some_missing(self):
        """Test when some expected ports are missing."""
        all_ports = [
            {"port": 80, "protocol": "tcp", "state": "open"},
        ]
        expected = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
            {"port": 8080, "protocol": "tcp"},
        ]

        missing = check_expected_ports(all_ports, expected)

        assert len(missing) == 2
        assert {"port": 443, "protocol": "tcp"} in missing
        assert {"port": 8080, "protocol": "tcp"} in missing

    def test_check_expected_ports_all_missing(self):
        """Test when all expected ports are missing."""
        all_ports = [
            {"port": 22, "protocol": "tcp", "state": "open"},
        ]
        expected = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]

        missing = check_expected_ports(all_ports, expected)

        assert len(missing) == 2
        assert {"port": 80, "protocol": "tcp"} in missing
        assert {"port": 443, "protocol": "tcp"} in missing

    def test_check_expected_ports_empty_scan(self):
        """Test when scan results are empty."""
        all_ports = []
        expected = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]

        missing = check_expected_ports(all_ports, expected)

        assert len(missing) == 2
        assert missing == expected
