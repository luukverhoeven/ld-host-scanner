"""Tests for port scanner functions."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from src.scanner.port_scanner import check_expected_ports


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
            "common_service": "http",
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

    def test_check_expected_ports_empty_expected(self):
        """Test when no ports are expected."""
        all_ports = [
            {"port": 80, "protocol": "tcp", "state": "open"},
        ]
        expected = []

        missing = check_expected_ports(all_ports, expected)

        assert missing == []

    def test_check_expected_ports_different_protocols(self):
        """Test protocol-specific matching (TCP port != UDP port)."""
        all_ports = [
            {"port": 53, "protocol": "tcp", "state": "open"},
        ]
        expected = [
            {"port": 53, "protocol": "udp"},  # Different protocol
        ]

        missing = check_expected_ports(all_ports, expected)

        assert len(missing) == 1
        assert missing[0] == {"port": 53, "protocol": "udp"}


class TestVersionDetectionArgs:
    """Tests for _version_detection_args static method."""

    def test_version_detection_args_light(self):
        """Test light intensity returns version-light."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

        result = scanner._version_detection_args("light")
        assert result == "-sV --version-light"

    def test_version_detection_args_thorough(self):
        """Test thorough intensity returns version-all."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

        result = scanner._version_detection_args("thorough")
        assert result == "-sV --version-all"

    def test_version_detection_args_normal(self):
        """Test normal intensity returns basic -sV."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

        result = scanner._version_detection_args("normal")
        assert result == "-sV"

    def test_version_detection_args_unknown(self):
        """Test unknown intensity defaults to basic -sV."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

        result = scanner._version_detection_args("unknown")
        assert result == "-sV"


class TestScanTcpRustscan:
    """Tests for scan_tcp_rustscan method."""

    def test_scan_tcp_rustscan_success(self):
        """Test successful Rustscan execution."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "example.com -> [22, 80, 443]"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = scanner.scan_tcp_rustscan("example.com", "1-65535")

        assert result["host_status"] == "up"
        assert len(result["ports"]) == 3
        assert mock_run.called

    def test_scan_tcp_rustscan_timeout(self):
        """Test Rustscan timeout raises exception."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

        from subprocess import TimeoutExpired
        with patch("subprocess.run", side_effect=TimeoutExpired("rustscan", 600)):
            with pytest.raises(TimeoutExpired):
                scanner.scan_tcp_rustscan("example.com")

    def test_scan_tcp_rustscan_not_found(self):
        """Test Rustscan binary not found raises exception."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            with pytest.raises(FileNotFoundError):
                scanner.scan_tcp_rustscan("example.com")

    def test_scan_tcp_rustscan_no_ports(self):
        """Test Rustscan with no open ports."""
        with patch("nmap.PortScanner"):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "example.com -> []"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = scanner.scan_tcp_rustscan("example.com")

        assert result["host_status"] == "up"
        assert result["ports"] == []


class TestCheckHostOnline:
    """Tests for check_host_online method."""

    def test_check_host_online_ip_match(self):
        """Test host online check with direct IP match."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_nm.__getitem__ = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.check_host_online("192.168.1.1")

        assert result is True

    def test_check_host_online_hostname_match(self):
        """Test host online check with hostname fallback."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.hostname.return_value = "example.com"
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.check_host_online("example.com")

        assert result is True

    def test_check_host_online_not_found(self):
        """Test host online check when host not in results."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = []

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.check_host_online("192.168.1.1")

        assert result is False

    def test_check_host_online_scan_error(self):
        """Test host online check with nmap error."""
        mock_nm = MagicMock()
        import nmap
        mock_nm.scan.side_effect = nmap.PortScannerError("Scan failed")

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.check_host_online("192.168.1.1")

        assert result is False


class TestParseResults:
    """Tests for _parse_results method."""

    def test_parse_results_with_ports(self):
        """Test parsing nmap results with open ports."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["tcp"]
        mock_host.__getitem__ = MagicMock(return_value={
            80: {"state": "open", "name": "http", "version": "nginx 1.18"},
            443: {"state": "open", "name": "https", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner._parse_results("192.168.1.1", "tcp")

        assert result["host_status"] == "up"
        assert len(result["ports"]) == 2

    def test_parse_results_target_not_found(self):
        """Test parsing when target not in results."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = []

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner._parse_results("192.168.1.1", "tcp")

        assert result["host_status"] == "down"
        assert result["ports"] == []

    def test_parse_results_filtered_state(self):
        """Test that filtered ports are excluded from results."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["tcp"]
        mock_host.__getitem__ = MagicMock(return_value={
            80: {"state": "filtered", "name": "http", "version": ""},
            443: {"state": "open", "name": "https", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner._parse_results("192.168.1.1", "tcp")

        # Only the open port should be included
        assert len(result["ports"]) == 1
        assert result["ports"][0]["port"] == 443


class TestFindNmapTargetKey:
    """Tests for _find_nmap_target_key method."""

    def test_find_nmap_target_key_direct_match(self):
        """Test direct IP match in nmap results."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1", "192.168.1.2"]

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner._find_nmap_target_key("192.168.1.1")

        assert result == "192.168.1.1"

    def test_find_nmap_target_key_hostname_fallback(self):
        """Test hostname fallback when IP doesn't match directly."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.hostname.return_value = "example.com"
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner._find_nmap_target_key("example.com")

        assert result == "192.168.1.1"

    def test_find_nmap_target_key_not_found(self):
        """Test when target not found in nmap results."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.hostname.return_value = "other.com"
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner._find_nmap_target_key("notfound.com")

        assert result is None


class TestUpdateExpectedPortsMetrics:
    """Tests for update_expected_ports_metrics function."""

    def test_update_metrics_all_ports_open(self):
        """Test metrics update when all expected ports are open."""
        from src.scanner.port_scanner import update_expected_ports_metrics

        expected = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]
        missing = []

        with patch("src.scanner.port_scanner.expected_port_status") as mock_status, \
             patch("src.scanner.port_scanner.expected_ports_missing") as mock_missing:
            mock_labels = MagicMock()
            mock_status.labels.return_value = mock_labels
            mock_missing.labels.return_value = mock_labels

            update_expected_ports_metrics("example.com", expected, missing)

        # Should be called twice (once per expected port)
        assert mock_status.labels.call_count == 2
        # Missing count should be set to 0
        mock_missing.labels.return_value.set.assert_called_with(0)

    def test_update_metrics_some_ports_missing(self):
        """Test metrics update when some expected ports are missing."""
        from src.scanner.port_scanner import update_expected_ports_metrics

        expected = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]
        missing = [
            {"port": 443, "protocol": "tcp"},
        ]

        with patch("src.scanner.port_scanner.expected_port_status") as mock_status, \
             patch("src.scanner.port_scanner.expected_ports_missing") as mock_missing:
            mock_labels = MagicMock()
            mock_status.labels.return_value = mock_labels
            mock_missing.labels.return_value = mock_labels

            update_expected_ports_metrics("example.com", expected, missing)

        # Missing count should be set to 1
        mock_missing.labels.return_value.set.assert_called_with(1)


class TestRunFullScan:
    """Tests for run_full_scan async function."""

    @pytest.mark.asyncio
    async def test_run_full_scan_success(self):
        """Test successful full scan execution."""
        from src.scanner.port_scanner import run_full_scan

        # Mock all the dependencies
        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.port_scanner.PortScanner") as mock_scanner_class, \
             patch("src.scanner.port_scanner.save_scan", new_callable=AsyncMock) as mock_save_scan, \
             patch("src.scanner.port_scanner.save_ports", new_callable=AsyncMock) as mock_save_ports, \
             patch("src.scanner.port_scanner.detect_changes", new_callable=AsyncMock) as mock_detect, \
             patch("src.scanner.port_scanner.init_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.add_log_entry", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_progress", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.delayed_cleanup", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.scan_duration_seconds"), \
             patch("src.scanner.port_scanner.open_ports_count"), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.scanner.port_scanner.port_changes_total"), \
             patch("src.scanner.port_scanner.scans_total"):

            mock_settings.target_host = "example.com"
            mock_settings.tcp_service_enrichment = False
            mock_settings.expected_ports_configured = False
            mock_settings.udp_top_ports = 1000

            # Mock scanner instance
            mock_scanner = MagicMock()
            mock_scanner.scan_tcp_rustscan.return_value = {
                "host_status": "up",
                "ports": [{"port": 80, "protocol": "tcp", "state": "open"}],
            }
            mock_scanner.scan_udp.return_value = {
                "host_status": "up",
                "ports": [],
            }
            mock_scanner_class.return_value = mock_scanner

            mock_detect.return_value = []

            result = await run_full_scan("manual")

        assert result is not None
        mock_save_scan.assert_awaited()
        mock_save_ports.assert_awaited()

    @pytest.mark.asyncio
    async def test_run_full_scan_with_changes(self):
        """Test full scan that detects port changes."""
        from src.scanner.port_scanner import run_full_scan

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.port_scanner.PortScanner") as mock_scanner_class, \
             patch("src.scanner.port_scanner.save_scan", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.save_ports", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.detect_changes", new_callable=AsyncMock) as mock_detect, \
             patch("src.scanner.port_scanner.init_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.add_log_entry", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_progress", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.delayed_cleanup", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.scan_duration_seconds"), \
             patch("src.scanner.port_scanner.open_ports_count"), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.scanner.port_scanner.port_changes_total") as mock_changes_metric, \
             patch("src.scanner.port_scanner.scans_total"), \
             patch("src.notifications.notifier.send_notifications", new_callable=AsyncMock) as mock_notify:

            mock_settings.target_host = "example.com"
            mock_settings.tcp_service_enrichment = False
            mock_settings.expected_ports_configured = False
            mock_settings.udp_top_ports = 1000

            mock_scanner = MagicMock()
            mock_scanner.scan_tcp_rustscan.return_value = {"host_status": "up", "ports": []}
            mock_scanner.scan_udp.return_value = {"host_status": "up", "ports": []}
            mock_scanner_class.return_value = mock_scanner

            # Return port changes
            mock_detect.return_value = [
                {"port": 443, "protocol": "tcp", "change_type": "opened"},
            ]

            result = await run_full_scan("scheduled")

        assert result is not None
        mock_notify.assert_awaited()

    @pytest.mark.asyncio
    async def test_run_full_scan_failure(self):
        """Test full scan that fails with exception."""
        from src.scanner.port_scanner import run_full_scan

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.port_scanner.PortScanner") as mock_scanner_class, \
             patch("src.scanner.port_scanner.save_scan", new_callable=AsyncMock) as mock_save_scan, \
             patch("src.scanner.port_scanner.init_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.add_log_entry", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_progress", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.delayed_cleanup", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.scans_total") as mock_scans_total:

            mock_settings.target_host = "example.com"
            mock_settings.udp_top_ports = 1000

            mock_scanner = MagicMock()
            mock_scanner.scan_tcp_rustscan.side_effect = Exception("Scan failed")
            mock_scanner_class.return_value = mock_scanner

            result = await run_full_scan("manual")

        assert result is None
        # Should save scan as failed
        call_args = mock_save_scan.call_args_list[-1]
        assert call_args.args[4] == "failed"  # status


class TestRunHostCheck:
    """Tests for run_host_check async function."""

    @pytest.mark.asyncio
    async def test_run_host_check_online(self):
        """Test host check when host is online."""
        from src.scanner.port_scanner import run_host_check

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.host_checker.quick_host_check", new_callable=AsyncMock) as mock_check, \
             patch("src.storage.database.get_last_host_status", new_callable=AsyncMock) as mock_prev, \
             patch("src.storage.database.save_host_status", new_callable=AsyncMock), \
             patch("src.storage.database.save_host_status_history", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.host_online_status"):

            mock_settings.target_host = "example.com"
            mock_settings.host_offline_threshold = 2

            mock_check.return_value = {
                "status": "online",
                "dns_resolved": True,
                "tcp_reachable": True,
                "icmp_reachable": True,
                "check_method": "icmp",
            }
            mock_prev.return_value = {"status": "online", "failure_count": 0}

            result = await run_host_check()

        assert result is True

    @pytest.mark.asyncio
    async def test_run_host_check_offline_threshold_not_reached(self):
        """Test host check when offline but threshold not reached."""
        from src.scanner.port_scanner import run_host_check

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.host_checker.quick_host_check", new_callable=AsyncMock) as mock_check, \
             patch("src.storage.database.get_last_host_status", new_callable=AsyncMock) as mock_prev, \
             patch("src.storage.database.save_host_status", new_callable=AsyncMock) as mock_save, \
             patch("src.storage.database.save_host_status_history", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.host_online_status"):

            mock_settings.target_host = "example.com"
            mock_settings.host_offline_threshold = 2

            mock_check.return_value = {
                "status": "offline",
                "dns_resolved": False,
                "tcp_reachable": False,
                "icmp_reachable": False,
                "check_method": "icmp",
            }
            # First failure - threshold not reached
            mock_prev.return_value = {"status": "online", "failure_count": 0}

            result = await run_host_check()

        assert result is False
        # Should save but not notify (threshold not reached)
        mock_save.assert_awaited()

    @pytest.mark.asyncio
    async def test_run_host_check_recovery(self):
        """Test host check recovery notification."""
        from src.scanner.port_scanner import run_host_check

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.host_checker.quick_host_check", new_callable=AsyncMock) as mock_check, \
             patch("src.storage.database.get_last_host_status", new_callable=AsyncMock) as mock_prev, \
             patch("src.storage.database.save_host_status", new_callable=AsyncMock), \
             patch("src.storage.database.save_host_status_history", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.notifications.notifier.send_host_status_notification", new_callable=AsyncMock) as mock_notify:

            mock_settings.target_host = "example.com"
            mock_settings.host_offline_threshold = 2

            mock_check.return_value = {
                "status": "online",
                "dns_resolved": True,
                "tcp_reachable": True,
                "icmp_reachable": True,
                "check_method": "tcp",
            }
            # Was offline, now online = recovery
            mock_prev.return_value = {"status": "offline", "failure_count": 3}

            result = await run_host_check()

        assert result is True
        mock_notify.assert_awaited_with("example.com", "online")


class TestScanTcp:
    """Tests for scan_tcp method."""

    def test_scan_tcp_with_ports(self):
        """Test TCP scan with discovered ports."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["tcp"]
        mock_host.__getitem__ = MagicMock(return_value={
            22: {"state": "open", "name": "ssh", "version": "OpenSSH 8.9"},
            80: {"state": "open", "name": "http", "version": "nginx"},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_tcp("192.168.1.1", "1-1000")

        assert result["host_status"] == "up"
        assert len(result["ports"]) == 2

    def test_scan_tcp_host_down(self):
        """Test TCP scan when host is down."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = []

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_tcp("192.168.1.1", "1-1000")

        assert result["host_status"] == "down"
        assert result["ports"] == []


class TestScanUdp:
    """Tests for scan_udp method."""

    def test_scan_udp_with_ports(self):
        """Test UDP scan with discovered ports."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["udp"]
        mock_host.__getitem__ = MagicMock(return_value={
            53: {"state": "open", "name": "dns", "version": ""},
            123: {"state": "open", "name": "ntp", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1", ports="53,123")

        assert result["host_status"] == "up"
        assert len(result["ports"]) == 2
        # All ports should be UDP
        for port in result["ports"]:
            assert port["protocol"] == "udp"

    def test_scan_udp_no_ports(self):
        """Test UDP scan with no open ports."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = []
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1")

        assert result["host_status"] == "up"
        assert result["ports"] == []


class TestEnrichTcpServices:
    """Tests for enrich_tcp_services method."""

    def test_enrich_tcp_services_basic(self):
        """Test TCP service enrichment."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["tcp"]
        mock_host.__getitem__ = MagicMock(return_value={
            80: {"state": "open", "name": "http", "version": "Apache 2.4", "product": "Apache"},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.enrich_tcp_services("192.168.1.1", [80], intensity="light")

        assert 80 in result
        assert result[80]["service"] == "http"

    def test_enrich_tcp_services_empty_ports(self):
        """Test TCP service enrichment with empty port list."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            # Empty port list should return empty dict without calling scan
            result = scanner.enrich_tcp_services("192.168.1.1", [], intensity="light")

        assert result == {}
        # scan should not have been called for empty ports
        mock_nm.scan.assert_not_called()


class TestScanSinglePort:
    """Tests for scan_single_port method."""

    def test_scan_single_port_open(self):
        """Test scanning a single open port."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.all_protocols.return_value = ["tcp"]
        mock_host.__getitem__ = MagicMock(return_value={
            80: {"state": "open", "name": "http", "version": "nginx 1.18"},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_single_port("192.168.1.1", 80, "tcp", "normal")

        assert result["port"] == 80
        assert result["protocol"] == "tcp"
        assert result["state"] == "open"
        assert result["service"] == "http"
        assert "scan_duration" in result

    def test_scan_single_port_closed(self):
        """Test scanning a closed port."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.all_protocols.return_value = ["tcp"]
        mock_host.__getitem__ = MagicMock(return_value={
            8080: {"state": "closed", "name": "", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_single_port("192.168.1.1", 8080, "tcp", "normal")

        assert result["port"] == 8080
        assert result["state"] == "closed"

    def test_scan_single_port_udp(self):
        """Test scanning a single UDP port."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.all_protocols.return_value = ["udp"]
        mock_host.__getitem__ = MagicMock(return_value={
            53: {"state": "open", "name": "dns", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_single_port("192.168.1.1", 53, "udp", "light")

        assert result["port"] == 53
        assert result["protocol"] == "udp"
        assert result["state"] == "open"
        assert result["service"] == "dns"

    def test_scan_single_port_target_not_found(self):
        """Test scanning when target not in results."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = []

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_single_port("192.168.1.1", 80, "tcp", "normal")

        assert result["state"] == "unknown"
        assert result["port"] == 80

    def test_scan_single_port_error(self):
        """Test scan_single_port handles nmap errors."""
        import nmap

        mock_nm = MagicMock()
        mock_nm.scan.side_effect = nmap.PortScannerError("Nmap failed")

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            with pytest.raises(nmap.PortScannerError):
                scanner.scan_single_port("192.168.1.1", 80, "tcp", "normal")


class TestScanTcpParallel:
    """Tests for scan_tcp_parallel async function."""

    @pytest.mark.asyncio
    async def test_scan_tcp_parallel_success(self):
        """Test parallel TCP scanning with multiple workers."""
        from src.scanner.port_scanner import scan_tcp_parallel

        mock_scanner = MagicMock()
        mock_scanner.scan_tcp.return_value = {
            "host_status": "up",
            "ports": [{"port": 80, "protocol": "tcp", "state": "open"}],
        }

        with patch("src.scanner.port_scanner.PortScanner", return_value=mock_scanner):
            result = await scan_tcp_parallel("192.168.1.1", workers=2)

        assert result["host_status"] == "up"
        # Should have ports from all batches
        assert len(result["ports"]) >= 1

    @pytest.mark.asyncio
    async def test_scan_tcp_parallel_batch_exception(self):
        """Test parallel scan handles batch exceptions."""
        from src.scanner.port_scanner import scan_tcp_parallel

        call_count = [0]

        def mock_scan_tcp(target, ports):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("Batch 1 failed")
            return {
                "host_status": "up",
                "ports": [{"port": 443, "protocol": "tcp"}],
            }

        mock_scanner = MagicMock()
        mock_scanner.scan_tcp.side_effect = mock_scan_tcp

        with patch("src.scanner.port_scanner.PortScanner", return_value=mock_scanner):
            result = await scan_tcp_parallel("192.168.1.1", workers=2)

        # Should still return results from successful batches
        assert "ports" in result
        assert "host_status" in result

    @pytest.mark.asyncio
    async def test_scan_tcp_parallel_all_host_down(self):
        """Test parallel scan when host is down in all batches."""
        from src.scanner.port_scanner import scan_tcp_parallel

        mock_scanner = MagicMock()
        mock_scanner.scan_tcp.return_value = {
            "host_status": "down",
            "ports": [],
        }

        with patch("src.scanner.port_scanner.PortScanner", return_value=mock_scanner):
            result = await scan_tcp_parallel("192.168.1.1", workers=2)

        assert result["host_status"] == "down"
        assert result["ports"] == []


class TestCheckExpectedPorts:
    """Tests for check_expected_ports function."""

    def test_check_expected_ports_all_open(self):
        """Test all expected ports are open."""
        from src.scanner.port_scanner import check_expected_ports

        all_ports = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
            {"port": 22, "protocol": "tcp"},
        ]
        expected = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]

        missing = check_expected_ports(all_ports, expected)

        assert missing == []

    def test_check_expected_ports_some_missing(self):
        """Test some expected ports are missing."""
        from src.scanner.port_scanner import check_expected_ports

        all_ports = [
            {"port": 80, "protocol": "tcp"},
        ]
        expected = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]

        missing = check_expected_ports(all_ports, expected)

        assert len(missing) == 1
        assert missing[0]["port"] == 443

    def test_check_expected_ports_all_missing(self):
        """Test all expected ports are missing."""
        from src.scanner.port_scanner import check_expected_ports

        all_ports = []
        expected = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]

        missing = check_expected_ports(all_ports, expected)

        assert len(missing) == 2

    def test_check_expected_ports_protocol_matters(self):
        """Test that protocol is considered in matching."""
        from src.scanner.port_scanner import check_expected_ports

        all_ports = [
            {"port": 53, "protocol": "tcp"},  # TCP DNS
        ]
        expected = [
            {"port": 53, "protocol": "udp"},  # UDP DNS expected
        ]

        missing = check_expected_ports(all_ports, expected)

        # Should be missing because protocol doesn't match
        assert len(missing) == 1
        assert missing[0]["port"] == 53
        assert missing[0]["protocol"] == "udp"


class TestVersionDetectionArgs:
    """Tests for _version_detection_args method."""

    def test_version_detection_light(self):
        """Test light version detection args."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

            args = scanner._version_detection_args("light")

        assert "-sV" in args
        assert "--version-light" in args

    def test_version_detection_normal(self):
        """Test normal version detection args."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

            args = scanner._version_detection_args("normal")

        assert args == "-sV"

    def test_version_detection_thorough(self):
        """Test thorough version detection args."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()

            args = scanner._version_detection_args("thorough")

        assert "-sV" in args
        assert "--version-all" in args


# =============================================================================
# Group 1: WireGuard Probing Tests (_probe_wireguard_ports)
# =============================================================================

class TestProbeWireguardPorts:
    """Tests for _probe_wireguard_ports method."""

    def test_probe_wireguard_ports_verified(self):
        """Test WireGuard probe succeeds and port is verified."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.wireguard_probe_ports_list = [51820]
            mock_settings.wireguard_public_key = "testkey123"

            scanner = PortScanner()

            ports = [
                {"port": 51820, "protocol": "udp", "common_service": "wireguard", "version": ""},
            ]

            with patch("src.scanner.wireguard_probe.WireGuardProbe") as mock_probe_class:
                mock_probe = MagicMock()
                mock_probe.probe.return_value = {
                    "verified": True,
                    "response_type": "cookie_reply",
                    "message": "WireGuard verified",
                }
                mock_probe_class.return_value = mock_probe

                scanner._probe_wireguard_ports("example.com", ports)

        assert ports[0]["is_stealth"] is False
        assert "verified" in ports[0]["version"]
        assert "cookie_reply" in ports[0]["version"]

    def test_probe_wireguard_ports_failed_wireguard_port(self):
        """Test probe fails on wireguard port marks as stealth."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.wireguard_probe_ports_list = [51820]
            mock_settings.wireguard_public_key = None

            scanner = PortScanner()

            ports = [
                {"port": 51820, "protocol": "udp", "common_service": "wireguard", "version": ""},
            ]

            with patch("src.scanner.wireguard_probe.WireGuardProbe") as mock_probe_class:
                mock_probe = MagicMock()
                mock_probe.probe.return_value = {
                    "verified": False,
                    "response_type": "timeout",
                    "message": "No response",
                }
                mock_probe_class.return_value = mock_probe

                scanner._probe_wireguard_ports("example.com", ports)

        assert ports[0]["is_stealth"] is True
        assert "stealth" in ports[0]["version"]

    def test_probe_wireguard_ports_failed_non_wireguard(self):
        """Test probe fails on non-wireguard port - debug log only."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.wireguard_probe_ports_list = [51821]  # Non-standard port
            mock_settings.wireguard_public_key = None

            scanner = PortScanner()

            # Port not identified as wireguard by service
            ports = [
                {"port": 51821, "protocol": "udp", "common_service": "unknown", "version": ""},
            ]

            with patch("src.scanner.wireguard_probe.WireGuardProbe") as mock_probe_class:
                mock_probe = MagicMock()
                mock_probe.probe.return_value = {
                    "verified": False,
                    "response_type": "timeout",
                    "message": "No response",
                }
                mock_probe_class.return_value = mock_probe

                scanner._probe_wireguard_ports("example.com", ports)

        # Should NOT be marked as stealth since not wireguard service
        assert ports[0].get("is_stealth") is None or ports[0].get("is_stealth") is False

    def test_probe_wireguard_ports_no_ports_to_probe(self):
        """Test probing when no WireGuard ports configured."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.wireguard_probe_ports_list = []
            mock_settings.wireguard_public_key = None

            scanner = PortScanner()

            ports = [
                {"port": 443, "protocol": "tcp", "common_service": "https"},
            ]

            with patch("src.scanner.wireguard_probe.WireGuardProbe") as mock_probe_class:
                scanner._probe_wireguard_ports("example.com", ports)

                # Should not even instantiate probe since no ports to check
                mock_probe_class.assert_not_called()

    def test_probe_wireguard_ports_mixed_results(self):
        """Test probing multiple ports with mixed verification results."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.wireguard_probe_ports_list = [51820, 51821]
            mock_settings.wireguard_public_key = "key123"

            scanner = PortScanner()

            ports = [
                {"port": 51820, "protocol": "udp", "common_service": "wireguard", "version": ""},
                {"port": 51821, "protocol": "udp", "common_service": "wireguard", "version": ""},
                {"port": 443, "protocol": "tcp", "common_service": "https"},  # Should be skipped
            ]

            call_count = [0]

            def mock_probe_call(target, port):
                call_count[0] += 1
                if port == 51820:
                    return {"verified": True, "response_type": "handshake_response", "message": "ok"}
                return {"verified": False, "response_type": "timeout", "message": "no response"}

            with patch("src.scanner.wireguard_probe.WireGuardProbe") as mock_probe_class:
                mock_probe = MagicMock()
                mock_probe.probe.side_effect = mock_probe_call
                mock_probe_class.return_value = mock_probe

                scanner._probe_wireguard_ports("example.com", ports)

        # First port should be verified
        assert ports[0]["is_stealth"] is False
        assert "verified" in ports[0]["version"]

        # Second port should be stealth
        assert ports[1]["is_stealth"] is True


# =============================================================================
# Group 2: Rustscan Error Handling Tests
# =============================================================================

class TestScanTcpRustscanErrors:
    """Tests for scan_tcp_rustscan error handling."""

    def test_scan_tcp_rustscan_error_with_stderr(self):
        """Test Rustscan exits non-zero with stderr logging."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("subprocess.run") as mock_run:
            from src.scanner.port_scanner import PortScanner

            mock_settings.rustscan_timeout = 1000
            mock_settings.rustscan_batch_size = 500
            mock_settings.rustscan_ulimit = 5000

            mock_run.return_value = MagicMock(
                returncode=1,
                stderr="Error: scan failed",
                stdout="",
            )

            scanner = PortScanner()
            result = scanner.scan_tcp_rustscan("example.com", "1-1000")

        # Should still return result (parsed from stdout)
        assert result["host_status"] == "down"
        assert result["ports"] == []

    def test_scan_tcp_rustscan_unexpected_exception(self):
        """Test Rustscan handles unexpected exception."""
        mock_nm = MagicMock()

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("subprocess.run") as mock_run:
            from src.scanner.port_scanner import PortScanner

            mock_settings.rustscan_timeout = 1000
            mock_settings.rustscan_batch_size = 500
            mock_settings.rustscan_ulimit = 5000

            mock_run.side_effect = RuntimeError("Unexpected subprocess error")

            scanner = PortScanner()

            with pytest.raises(RuntimeError) as exc_info:
                scanner.scan_tcp_rustscan("example.com", "1-1000")

            assert "Unexpected subprocess error" in str(exc_info.value)


# =============================================================================
# Group 3: Exception Handler Tests
# =============================================================================

class TestCheckHostOnlineExceptions:
    """Tests for check_host_online exception handling."""

    def test_check_host_online_unexpected_exception(self):
        """Test check_host_online handles unexpected exception."""
        mock_nm = MagicMock()
        mock_nm.scan.side_effect = RuntimeError("Unexpected network error")

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.check_host_online("example.com")

        assert result is False


class TestScanTcpExceptions:
    """Tests for scan_tcp exception handling."""

    def test_scan_tcp_port_scanner_error(self):
        """Test scan_tcp handles PortScannerError."""
        import nmap

        mock_nm = MagicMock()
        mock_nm.scan.side_effect = nmap.PortScannerError("Nmap scan failed")

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            with pytest.raises(nmap.PortScannerError):
                scanner.scan_tcp("example.com", "1-1000")

    def test_scan_tcp_unexpected_exception(self):
        """Test scan_tcp handles unexpected exception."""
        mock_nm = MagicMock()
        mock_nm.scan.side_effect = RuntimeError("Network error")

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            with pytest.raises(RuntimeError):
                scanner.scan_tcp("example.com", "1-1000")


class TestScanUdpExceptions:
    """Tests for scan_udp exception handling."""

    def test_scan_udp_port_scanner_error(self):
        """Test scan_udp handles PortScannerError."""
        import nmap

        mock_nm = MagicMock()
        mock_nm.scan.side_effect = nmap.PortScannerError("Nmap UDP scan failed")

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.expected_ports_list = []
            mock_settings.wireguard_probe_ports_list = []
            mock_settings.udp_top_ports = 1000
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"

            scanner = PortScanner()
            scanner.nm = mock_nm

            with pytest.raises(nmap.PortScannerError):
                scanner.scan_udp("example.com")

    def test_scan_udp_unexpected_exception(self):
        """Test scan_udp handles unexpected exception."""
        mock_nm = MagicMock()
        mock_nm.scan.side_effect = RuntimeError("UDP network error")

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.expected_ports_list = []
            mock_settings.wireguard_probe_ports_list = []
            mock_settings.udp_top_ports = 1000
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"

            scanner = PortScanner()
            scanner.nm = mock_nm

            with pytest.raises(RuntimeError):
                scanner.scan_udp("example.com")


class TestScanSinglePortExceptions:
    """Tests for scan_single_port exception handling."""

    def test_scan_single_port_unexpected_exception(self):
        """Test scan_single_port handles unexpected exception (not PortScannerError)."""
        mock_nm = MagicMock()
        mock_nm.scan.side_effect = OSError("Socket error")

        with patch("nmap.PortScanner", return_value=mock_nm):
            from src.scanner.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.nm = mock_nm

            with pytest.raises(OSError):
                scanner.scan_single_port("example.com", 80, "tcp", "normal")


# =============================================================================
# Group 4: UDP Multi-Phase Logic Tests
# =============================================================================

class TestScanUdpMultiPhase:
    """Tests for scan_udp multi-phase logic."""

    def test_scan_udp_with_extra_ports(self):
        """Test UDP scan with extra ports from expected/wireguard config."""
        mock_nm = MagicMock()

        # Setup mock to return ports only on second call (Phase 1b: extra ports)
        call_count = [0]

        def mock_scan_side_effect(*args, **kwargs):
            call_count[0] += 1

        mock_nm.scan.side_effect = mock_scan_side_effect
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["udp"]
        mock_host.__getitem__ = MagicMock(return_value={
            53: {"state": "open", "name": "dns", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            # Configure expected UDP port
            mock_settings.expected_ports_list = [{"port": 53, "protocol": "udp"}]
            mock_settings.wireguard_probe_ports_list = [51820]
            mock_settings.udp_top_ports = 100
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"
            mock_settings.udp_version_detection = False
            mock_settings.wireguard_configured = False

            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1")

        # Should have called scan twice (Phase 1a + Phase 1b for extra ports)
        assert call_count[0] >= 2
        assert result["host_status"] == "up"

    def test_scan_udp_target_not_found(self):
        """Test UDP scan when target not found in nmap results."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = []  # No hosts found

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.expected_ports_list = []
            mock_settings.wireguard_probe_ports_list = []
            mock_settings.udp_top_ports = 100
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"
            mock_settings.udp_version_detection = False
            mock_settings.wireguard_configured = False

            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1")

        assert result["host_status"] == "down"
        assert result["ports"] == []

    def test_scan_udp_filtered_states(self):
        """Test UDP scan filters out non-open states."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["udp"]
        # Include ports with different states
        mock_host.__getitem__ = MagicMock(return_value={
            53: {"state": "open", "name": "dns", "version": ""},
            123: {"state": "closed", "name": "ntp", "version": ""},  # Should be filtered
            161: {"state": "filtered", "name": "snmp", "version": ""},  # Should be filtered
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.expected_ports_list = []
            mock_settings.wireguard_probe_ports_list = []
            mock_settings.udp_top_ports = 100
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"
            mock_settings.udp_version_detection = False
            mock_settings.wireguard_configured = False

            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1", ports="53,123,161")

        # Only port 53 (open) should be included
        assert len(result["ports"]) == 1
        assert result["ports"][0]["port"] == 53

    def test_scan_udp_deduplicate_ports(self):
        """Test UDP scan deduplicates ports from multiple scan phases."""
        mock_nm = MagicMock()

        # Track scan calls
        scan_call_count = [0]

        def mock_scan(*args, **kwargs):
            scan_call_count[0] += 1

        mock_nm.scan.side_effect = mock_scan
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["udp"]
        # Same port returned in both phases
        mock_host.__getitem__ = MagicMock(return_value={
            53: {"state": "open", "name": "dns", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            # Port 53 is both a top port AND an expected port
            mock_settings.expected_ports_list = [{"port": 53, "protocol": "udp"}]
            mock_settings.wireguard_probe_ports_list = []
            mock_settings.udp_top_ports = 100
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"
            mock_settings.udp_version_detection = False
            mock_settings.wireguard_configured = False

            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1")

        # Port 53 should appear only once despite being found in multiple phases
        port_53_entries = [p for p in result["ports"] if p["port"] == 53]
        assert len(port_53_entries) == 1

    def test_scan_udp_expected_port_priority(self):
        """Test expected ports get higher priority in version detection."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["udp"]
        mock_host.__getitem__ = MagicMock(return_value={
            53: {"state": "open", "name": "dns", "version": ""},
            123: {"state": "open", "name": "ntp", "version": ""},
            5000: {"state": "open", "name": "unknown", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            # Port 5000 is expected but not a known service
            mock_settings.expected_ports_list = [{"port": 5000, "protocol": "udp"}]
            mock_settings.wireguard_probe_ports_list = []
            mock_settings.udp_top_ports = 100
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"
            mock_settings.udp_version_detection = True
            mock_settings.udp_version_detection_intensity = "normal"
            mock_settings.udp_version_detection_ports_limit = 10
            mock_settings.wireguard_configured = False

            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1", ports="53,123,5000")

        # All open ports should be in results
        assert len(result["ports"]) == 3

    def test_scan_udp_version_limit_reached(self):
        """Test UDP version detection stops at limit."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["udp"]
        mock_host.__getitem__ = MagicMock(return_value={
            53: {"state": "open", "name": "dns", "version": ""},
            123: {"state": "open", "name": "ntp", "version": ""},
            161: {"state": "open", "name": "snmp", "version": ""},
            500: {"state": "open", "name": "isakmp", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        scan_calls = []

        def track_scan(*args, **kwargs):
            scan_calls.append(kwargs.get("ports"))

        mock_nm.scan.side_effect = track_scan

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.expected_ports_list = []
            mock_settings.wireguard_probe_ports_list = []
            mock_settings.udp_top_ports = 100
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"
            mock_settings.udp_version_detection = True
            mock_settings.udp_version_detection_intensity = "light"
            mock_settings.udp_version_detection_ports_limit = 2  # Only version scan 2 ports
            mock_settings.wireguard_configured = False

            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1", ports="53,123,161,500")

        # All ports should be discovered
        assert len(result["ports"]) == 4

    def test_scan_udp_no_version_entry(self):
        """Test UDP port not in version detection results - port preserved from discovery."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["udp"]
        # Port found in discovery with basic info
        mock_host.__getitem__ = MagicMock(return_value={
            53: {"state": "open", "name": "dns", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.expected_ports_list = []
            mock_settings.wireguard_probe_ports_list = []
            mock_settings.udp_top_ports = 100
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"
            mock_settings.udp_version_detection = True
            mock_settings.udp_version_detection_intensity = "normal"
            mock_settings.udp_version_detection_ports_limit = 10
            mock_settings.wireguard_configured = False

            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1", ports="53")

        # Port should be in results
        assert len(result["ports"]) == 1
        assert result["ports"][0]["port"] == 53

    def test_scan_udp_wireguard_probing(self):
        """Test UDP scan triggers WireGuard probing when configured."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["udp"]
        mock_host.__getitem__ = MagicMock(return_value={
            51820: {"state": "open|filtered", "name": "unknown", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        wireguard_probe_called = [False]

        def mock_probe_wireguard(target, ports):
            wireguard_probe_called[0] = True

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.expected_ports_list = []
            mock_settings.wireguard_probe_ports_list = [51820]
            mock_settings.udp_top_ports = 100
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"
            mock_settings.udp_version_detection = False
            mock_settings.wireguard_configured = True  # Enable WireGuard probing
            mock_settings.wireguard_public_key = "testkey"

            scanner = PortScanner()
            scanner.nm = mock_nm
            scanner._probe_wireguard_ports = mock_probe_wireguard

            result = scanner.scan_udp("192.168.1.1", ports="51820")

        assert wireguard_probe_called[0] is True
        assert len(result["ports"]) == 1

    def test_scan_udp_open_filtered_state(self):
        """Test UDP scan accepts open|filtered state."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1"]
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        mock_host.all_protocols.return_value = ["udp"]
        mock_host.__getitem__ = MagicMock(return_value={
            53: {"state": "open|filtered", "name": "dns", "version": ""},
        })
        mock_nm.__getitem__ = MagicMock(return_value=mock_host)

        with patch("nmap.PortScanner", return_value=mock_nm), \
             patch("src.scanner.port_scanner.settings") as mock_settings:
            from src.scanner.port_scanner import PortScanner

            mock_settings.expected_ports_list = []
            mock_settings.wireguard_probe_ports_list = []
            mock_settings.udp_top_ports = 100
            mock_settings.scan_timing = 4
            mock_settings.scan_min_rate = 0
            mock_settings.scan_host_timeout = "300s"
            mock_settings.udp_version_detection = False
            mock_settings.wireguard_configured = False

            scanner = PortScanner()
            scanner.nm = mock_nm

            result = scanner.scan_udp("192.168.1.1", ports="53")

        # Port with open|filtered state should be included
        assert len(result["ports"]) == 1
        assert result["ports"][0]["port"] == 53
        assert result["ports"][0]["state"] == "open"  # Normalized


# =============================================================================
# Group 5: Full Scan Integration Tests
# =============================================================================

class TestRunFullScanIntegration:
    """Tests for run_full_scan integration scenarios."""

    @pytest.mark.asyncio
    async def test_run_full_scan_tcp_enrichment_success(self):
        """Test full scan with TCP service enrichment enabled."""
        from src.scanner.port_scanner import run_full_scan

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.port_scanner.PortScanner") as mock_scanner_class, \
             patch("src.scanner.port_scanner.save_scan", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.save_ports", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.detect_changes", new_callable=AsyncMock) as mock_detect, \
             patch("src.scanner.port_scanner.init_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.add_log_entry", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_progress", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.delayed_cleanup", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.scan_duration_seconds"), \
             patch("src.scanner.port_scanner.open_ports_count"), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.scanner.port_scanner.port_changes_total"), \
             patch("src.scanner.port_scanner.scans_total"):

            mock_settings.target_host = "example.com"
            mock_settings.tcp_service_enrichment = True  # Enable enrichment
            mock_settings.tcp_service_enrichment_ports_limit = 10
            mock_settings.tcp_service_enrichment_intensity = "normal"
            mock_settings.expected_ports_configured = False
            mock_settings.udp_top_ports = 1000

            mock_scanner = MagicMock()
            mock_scanner.scan_tcp_rustscan.return_value = {
                "host_status": "up",
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "unknown", "version": ""},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "unknown", "version": ""},
                ],
            }
            mock_scanner.scan_udp.return_value = {"host_status": "up", "ports": []}
            mock_scanner.enrich_tcp_services.return_value = {
                80: {"service": "http", "version": "Apache 2.4"},
                443: {"service": "https", "version": "nginx 1.18"},
            }
            mock_scanner_class.return_value = mock_scanner

            mock_detect.return_value = []

            result = await run_full_scan("manual")

        assert result is not None
        mock_scanner.enrich_tcp_services.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_full_scan_tcp_enrichment_failure(self):
        """Test full scan continues when enrichment fails."""
        from src.scanner.port_scanner import run_full_scan

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.port_scanner.PortScanner") as mock_scanner_class, \
             patch("src.scanner.port_scanner.save_scan", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.save_ports", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.detect_changes", new_callable=AsyncMock) as mock_detect, \
             patch("src.scanner.port_scanner.init_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.add_log_entry", new_callable=AsyncMock) as mock_log, \
             patch("src.scanner.port_scanner.update_scan_progress", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.delayed_cleanup", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.scan_duration_seconds"), \
             patch("src.scanner.port_scanner.open_ports_count"), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.scanner.port_scanner.port_changes_total"), \
             patch("src.scanner.port_scanner.scans_total"):

            mock_settings.target_host = "example.com"
            mock_settings.tcp_service_enrichment = True
            mock_settings.tcp_service_enrichment_ports_limit = 10
            mock_settings.tcp_service_enrichment_intensity = "normal"
            mock_settings.expected_ports_configured = False
            mock_settings.udp_top_ports = 1000

            mock_scanner = MagicMock()
            mock_scanner.scan_tcp_rustscan.return_value = {
                "host_status": "up",
                "ports": [{"port": 80, "protocol": "tcp", "state": "open"}],
            }
            mock_scanner.scan_udp.return_value = {"host_status": "up", "ports": []}
            mock_scanner.enrich_tcp_services.side_effect = Exception("Enrichment failed")
            mock_scanner_class.return_value = mock_scanner

            mock_detect.return_value = []

            result = await run_full_scan("manual")

        # Scan should still complete successfully
        assert result is not None
        # Warning log should be added
        warning_calls = [c for c in mock_log.call_args_list if "failed" in str(c).lower()]
        assert len(warning_calls) > 0

    @pytest.mark.asyncio
    async def test_run_full_scan_expected_ports_none_missing(self):
        """Test full scan when all expected ports are open."""
        from src.scanner.port_scanner import run_full_scan

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.port_scanner.PortScanner") as mock_scanner_class, \
             patch("src.scanner.port_scanner.save_scan", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.save_ports", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.detect_changes", new_callable=AsyncMock) as mock_detect, \
             patch("src.scanner.port_scanner.check_expected_ports") as mock_check, \
             patch("src.scanner.port_scanner.update_expected_ports_metrics") as mock_metrics, \
             patch("src.scanner.port_scanner.get_previous_missing_expected_ports", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.detect_newly_missing_expected_ports") as mock_detect_newly, \
             patch("src.scanner.port_scanner.init_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.add_log_entry", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_progress", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.delayed_cleanup", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.scan_duration_seconds"), \
             patch("src.scanner.port_scanner.open_ports_count"), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.scanner.port_scanner.port_changes_total"), \
             patch("src.scanner.port_scanner.scans_total"):

            mock_settings.target_host = "example.com"
            mock_settings.tcp_service_enrichment = False
            mock_settings.expected_ports_configured = True  # Enable expected ports check
            mock_settings.expected_ports_list = [{"port": 80, "protocol": "tcp"}]
            mock_settings.udp_top_ports = 1000

            mock_scanner = MagicMock()
            mock_scanner.scan_tcp_rustscan.return_value = {
                "host_status": "up",
                "ports": [{"port": 80, "protocol": "tcp", "state": "open"}],
            }
            mock_scanner.scan_udp.return_value = {"host_status": "up", "ports": []}
            mock_scanner_class.return_value = mock_scanner

            mock_detect.return_value = []
            mock_check.return_value = []  # No missing ports
            mock_detect_newly.return_value = []

            result = await run_full_scan("manual")

        assert result is not None
        mock_check.assert_called_once()
        mock_metrics.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_full_scan_expected_ports_newly_missing(self):
        """Test full scan sends notification for newly missing expected ports."""
        from src.scanner.port_scanner import run_full_scan

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.port_scanner.PortScanner") as mock_scanner_class, \
             patch("src.scanner.port_scanner.save_scan", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.save_ports", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.detect_changes", new_callable=AsyncMock) as mock_detect, \
             patch("src.scanner.port_scanner.check_expected_ports") as mock_check, \
             patch("src.scanner.port_scanner.update_expected_ports_metrics"), \
             patch("src.scanner.port_scanner.get_previous_missing_expected_ports", new_callable=AsyncMock) as mock_prev, \
             patch("src.scanner.port_scanner.detect_newly_missing_expected_ports") as mock_detect_newly, \
             patch("src.notifications.notifier.send_missing_ports_notification", new_callable=AsyncMock) as mock_notify, \
             patch("src.scanner.port_scanner.init_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.add_log_entry", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_progress", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.delayed_cleanup", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.scan_duration_seconds"), \
             patch("src.scanner.port_scanner.open_ports_count"), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.scanner.port_scanner.port_changes_total"), \
             patch("src.scanner.port_scanner.scans_total"):

            mock_settings.target_host = "example.com"
            mock_settings.tcp_service_enrichment = False
            mock_settings.expected_ports_configured = True
            mock_settings.expected_ports_list = [
                {"port": 80, "protocol": "tcp"},
                {"port": 443, "protocol": "tcp"},
            ]
            mock_settings.udp_top_ports = 1000

            mock_scanner = MagicMock()
            mock_scanner.scan_tcp_rustscan.return_value = {
                "host_status": "up",
                "ports": [{"port": 80, "protocol": "tcp", "state": "open"}],  # 443 is missing
            }
            mock_scanner.scan_udp.return_value = {"host_status": "up", "ports": []}
            mock_scanner_class.return_value = mock_scanner

            mock_detect.return_value = []
            mock_check.return_value = [{"port": 443, "protocol": "tcp"}]  # 443 missing
            mock_prev.return_value = []  # Was not missing before
            mock_detect_newly.return_value = [{"port": 443, "protocol": "tcp"}]  # Newly missing

            result = await run_full_scan("manual")

        assert result is not None
        mock_notify.assert_awaited_once_with("example.com", [{"port": 443, "protocol": "tcp"}])

    @pytest.mark.asyncio
    async def test_run_full_scan_expected_ports_still_missing(self):
        """Test full scan logs when expected ports are still missing (no change)."""
        from src.scanner.port_scanner import run_full_scan

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.port_scanner.PortScanner") as mock_scanner_class, \
             patch("src.scanner.port_scanner.save_scan", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.save_ports", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.detect_changes", new_callable=AsyncMock) as mock_detect, \
             patch("src.scanner.port_scanner.check_expected_ports") as mock_check, \
             patch("src.scanner.port_scanner.update_expected_ports_metrics"), \
             patch("src.scanner.port_scanner.get_previous_missing_expected_ports", new_callable=AsyncMock) as mock_prev, \
             patch("src.scanner.port_scanner.detect_newly_missing_expected_ports") as mock_detect_newly, \
             patch("src.notifications.notifier.send_missing_ports_notification", new_callable=AsyncMock) as mock_notify, \
             patch("src.scanner.port_scanner.init_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.add_log_entry", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_progress", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.update_scan_state", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.delayed_cleanup", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.scan_duration_seconds"), \
             patch("src.scanner.port_scanner.open_ports_count"), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.scanner.port_scanner.port_changes_total"), \
             patch("src.scanner.port_scanner.scans_total"):

            mock_settings.target_host = "example.com"
            mock_settings.tcp_service_enrichment = False
            mock_settings.expected_ports_configured = True
            mock_settings.expected_ports_list = [{"port": 443, "protocol": "tcp"}]
            mock_settings.udp_top_ports = 1000

            mock_scanner = MagicMock()
            mock_scanner.scan_tcp_rustscan.return_value = {"host_status": "up", "ports": []}
            mock_scanner.scan_udp.return_value = {"host_status": "up", "ports": []}
            mock_scanner_class.return_value = mock_scanner

            mock_detect.return_value = []
            mock_check.return_value = [{"port": 443, "protocol": "tcp"}]  # Still missing
            mock_prev.return_value = [{"port": 443, "protocol": "tcp"}]  # Was already missing
            mock_detect_newly.return_value = []  # No change

            result = await run_full_scan("manual")

        assert result is not None
        # Should NOT send notification since port was already missing
        mock_notify.assert_not_awaited()


# =============================================================================
# Group 6: Host Check Threshold Tests
# =============================================================================

class TestRunHostCheckThreshold:
    """Tests for run_host_check threshold-based alerting."""

    @pytest.mark.asyncio
    async def test_run_host_check_offline_threshold_reached(self):
        """Test host check sends offline notification when threshold reached."""
        from src.scanner.port_scanner import run_host_check

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.host_checker.quick_host_check", new_callable=AsyncMock) as mock_check, \
             patch("src.storage.database.get_last_host_status", new_callable=AsyncMock) as mock_prev, \
             patch("src.storage.database.save_host_status", new_callable=AsyncMock) as mock_save, \
             patch("src.storage.database.save_host_status_history", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.notifications.notifier.send_host_status_notification", new_callable=AsyncMock) as mock_notify:

            mock_settings.target_host = "example.com"
            mock_settings.host_offline_threshold = 2

            mock_check.return_value = {
                "status": "offline",
                "dns_resolved": False,
                "tcp_reachable": False,
                "ping_reachable": False,
                "method": None,
            }
            mock_prev.return_value = "online"  # Was online
            mock_save.return_value = 2  # Failure count = threshold

            result = await run_host_check()

        assert result is False
        mock_notify.assert_awaited_with("example.com", "offline")

    @pytest.mark.asyncio
    async def test_run_host_check_offline_threshold_not_reached(self):
        """Test host check doesn't notify when threshold not reached."""
        from src.scanner.port_scanner import run_host_check

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.host_checker.quick_host_check", new_callable=AsyncMock) as mock_check, \
             patch("src.storage.database.get_last_host_status", new_callable=AsyncMock) as mock_prev, \
             patch("src.storage.database.save_host_status", new_callable=AsyncMock) as mock_save, \
             patch("src.storage.database.save_host_status_history", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.notifications.notifier.send_host_status_notification", new_callable=AsyncMock) as mock_notify:

            mock_settings.target_host = "example.com"
            mock_settings.host_offline_threshold = 3  # Need 3 failures

            mock_check.return_value = {
                "status": "offline",
                "dns_resolved": False,
                "tcp_reachable": False,
                "ping_reachable": False,
                "method": None,
            }
            mock_prev.return_value = "online"  # Was online
            mock_save.return_value = 1  # Only 1 failure so far

            result = await run_host_check()

        assert result is False
        # Should NOT send notification - threshold not reached
        mock_notify.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_host_check_still_offline_no_notification(self):
        """Test host check doesn't re-notify when already offline."""
        from src.scanner.port_scanner import run_host_check

        with patch("src.scanner.port_scanner.settings") as mock_settings, \
             patch("src.scanner.host_checker.quick_host_check", new_callable=AsyncMock) as mock_check, \
             patch("src.storage.database.get_last_host_status", new_callable=AsyncMock) as mock_prev, \
             patch("src.storage.database.save_host_status", new_callable=AsyncMock) as mock_save, \
             patch("src.storage.database.save_host_status_history", new_callable=AsyncMock), \
             patch("src.scanner.port_scanner.host_online_status"), \
             patch("src.notifications.notifier.send_host_status_notification", new_callable=AsyncMock) as mock_notify:

            mock_settings.target_host = "example.com"
            mock_settings.host_offline_threshold = 2

            mock_check.return_value = {
                "status": "offline",
                "dns_resolved": False,
                "tcp_reachable": False,
                "ping_reachable": False,
                "method": None,
            }
            mock_prev.return_value = "offline"  # Was already offline
            mock_save.return_value = 5  # Many failures

            result = await run_host_check()

        assert result is False
        # Should NOT send notification - already offline (no state change)
        mock_notify.assert_not_awaited()
