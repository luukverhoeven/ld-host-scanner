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
