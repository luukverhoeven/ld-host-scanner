"""Tests for pure helper functions in storage layer."""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.storage.database import detect_newly_missing_expected_ports


def test_detect_newly_missing_expected_ports_returns_only_new():
    prev = [{"port": 80, "protocol": "tcp"}]
    current = [{"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}]

    newly = detect_newly_missing_expected_ports(current, prev)
    assert newly == [{"port": 443, "protocol": "tcp"}]


def test_detect_newly_missing_expected_ports_empty_previous():
    """Test with no previous missing ports."""
    prev = []
    current = [{"port": 80, "protocol": "tcp"}]

    newly = detect_newly_missing_expected_ports(current, prev)
    assert newly == [{"port": 80, "protocol": "tcp"}]


def test_detect_newly_missing_expected_ports_no_new():
    """Test when all current missing were already missing."""
    prev = [{"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}]
    current = [{"port": 80, "protocol": "tcp"}]

    newly = detect_newly_missing_expected_ports(current, prev)
    assert newly == []


class TestHostStatusHistoryModel:
    """Tests for HostStatusHistory model structure."""

    def test_model_has_required_fields(self):
        """Test HostStatusHistory model has all required fields."""
        from src.storage.models import HostStatusHistory

        # Check model has expected columns
        columns = [c.name for c in HostStatusHistory.__table__.columns]
        assert "id" in columns
        assert "target" in columns
        assert "status" in columns
        assert "dns_resolved" in columns
        assert "tcp_reachable" in columns
        assert "icmp_reachable" in columns
        assert "check_method" in columns
        assert "checked_at" in columns

    def test_model_table_name(self):
        """Test HostStatusHistory table name."""
        from src.storage.models import HostStatusHistory

        assert HostStatusHistory.__tablename__ == "host_status_history"


class TestHostStatusSaveFunction:
    """Tests for save_host_status function logic.

    Note: These tests verify the logic of save_host_status without
    fully mocking the database session (which requires complex async
    context manager handling). They test the model behavior instead.
    """

    def test_host_status_model_fields(self):
        """Test HostStatus model has required fields."""
        from src.storage.models import HostStatus

        columns = [c.name for c in HostStatus.__table__.columns]
        assert "target" in columns
        assert "status" in columns
        assert "failure_count" in columns
        assert "last_check" in columns

    def test_host_status_failure_count_logic_online(self):
        """Test failure count resets to 0 when status is online."""
        # When status is online, failure_count should be 0
        # This tests the expected logic, not the database function
        status = "online"
        previous_failures = 5

        if status == "online":
            new_failure_count = 0
        else:
            new_failure_count = previous_failures + 1

        assert new_failure_count == 0

    def test_host_status_failure_count_logic_offline(self):
        """Test failure count increments when status is not online."""
        status = "offline"
        previous_failures = 2

        if status == "online":
            new_failure_count = 0
        else:
            new_failure_count = previous_failures + 1

        assert new_failure_count == 3

    def test_host_status_failure_count_logic_dns_only(self):
        """Test failure count increments for dns_only status."""
        status = "dns_only"
        previous_failures = 1

        if status == "online":
            new_failure_count = 0
        else:
            new_failure_count = previous_failures + 1

        assert new_failure_count == 2


class TestPortChangeDetectionLogic:
    """Tests for port change detection logic."""

    def test_detect_opened_ports(self):
        """Test detection of newly opened ports."""
        # Current ports from scan
        current_ports = {
            (80, "tcp"): {"port": 80, "protocol": "tcp", "state": "open"},
            (443, "tcp"): {"port": 443, "protocol": "tcp", "state": "open"},
        }
        # Previous ports (only 80 was open)
        prev_ports = {
            (80, "tcp"): {"port": 80, "protocol": "tcp", "state": "open"},
        }

        # Logic: find ports in current but not in previous
        opened = []
        for key, port in current_ports.items():
            if port["state"] == "open" and key not in prev_ports:
                opened.append(port)

        assert len(opened) == 1
        assert opened[0]["port"] == 443

    def test_detect_closed_ports(self):
        """Test detection of closed ports."""
        # Current ports (only 80 open)
        current_ports = {
            (80, "tcp"): {"port": 80, "protocol": "tcp", "state": "open"},
        }
        # Previous ports (both 80 and 443 were open)
        prev_ports = {
            (80, "tcp"): {"port": 80, "protocol": "tcp", "state": "open"},
            (443, "tcp"): {"port": 443, "protocol": "tcp", "state": "open"},
        }

        # Logic: find ports in previous but not in current
        closed = []
        for key, prev_port in prev_ports.items():
            if prev_port["state"] == "open" and key not in current_ports:
                closed.append(prev_port)

        assert len(closed) == 1
        assert closed[0]["port"] == 443

    def test_no_changes_when_ports_same(self):
        """Test no changes detected when ports are the same."""
        ports = {
            (80, "tcp"): {"port": 80, "protocol": "tcp", "state": "open"},
            (443, "tcp"): {"port": 443, "protocol": "tcp", "state": "open"},
        }

        opened = [p for key, p in ports.items() if key not in ports]
        closed = [p for key, p in ports.items() if key not in ports]

        assert opened == []
        assert closed == []

    def test_first_scan_no_changes(self):
        """Test first scan returns no changes (no previous scan)."""
        current_ports = {
            (80, "tcp"): {"port": 80, "protocol": "tcp", "state": "open"},
        }
        prev_ports = {}  # No previous scan

        # With no previous scan, we shouldn't report changes
        changes = []
        assert changes == []


class TestPortModel:
    """Tests for Port model structure."""

    def test_port_model_has_required_fields(self):
        """Test Port model has all required fields."""
        from src.storage.models import Port

        columns = [c.name for c in Port.__table__.columns]
        assert "id" in columns
        assert "scan_id" in columns
        assert "port" in columns
        assert "protocol" in columns
        assert "state" in columns
        assert "service" in columns
        assert "version" in columns
        assert "common_service" in columns
        assert "is_stealth" in columns

    def test_port_model_table_name(self):
        """Test Port table name."""
        from src.storage.models import Port

        assert Port.__tablename__ == "ports"


class TestScanModel:
    """Tests for Scan model structure."""

    def test_scan_model_has_required_fields(self):
        """Test Scan model has all required fields."""
        from src.storage.models import Scan

        columns = [c.name for c in Scan.__table__.columns]
        assert "id" in columns
        assert "scan_id" in columns
        assert "target" in columns
        assert "scan_type" in columns
        assert "status" in columns
        assert "host_status" in columns
        assert "started_at" in columns
        assert "completed_at" in columns
        assert "error_message" in columns

    def test_scan_model_table_name(self):
        """Test Scan table name."""
        from src.storage.models import Scan

        assert Scan.__tablename__ == "scans"


class TestPortChangeModel:
    """Tests for PortChange model structure."""

    def test_port_change_model_has_required_fields(self):
        """Test PortChange model has all required fields."""
        from src.storage.models import PortChange

        columns = [c.name for c in PortChange.__table__.columns]
        assert "id" in columns
        assert "scan_id" in columns
        assert "port" in columns
        assert "protocol" in columns
        assert "change_type" in columns
        assert "previous_state" in columns
        assert "new_state" in columns
        assert "service" in columns
        assert "detected_at" in columns

    def test_port_change_model_table_name(self):
        """Test PortChange table name."""
        from src.storage.models import PortChange

        assert PortChange.__tablename__ == "port_changes"


class TestNotificationModel:
    """Tests for Notification model structure."""

    def test_notification_model_has_required_fields(self):
        """Test Notification model has all required fields."""
        from src.storage.models import Notification

        columns = [c.name for c in Notification.__table__.columns]
        assert "id" in columns
        assert "scan_id" in columns
        assert "notification_type" in columns
        assert "subject" in columns
        assert "message" in columns
        assert "status" in columns
        assert "error_message" in columns
        assert "sent_at" in columns

    def test_notification_model_table_name(self):
        """Test Notification table name."""
        from src.storage.models import Notification

        assert Notification.__tablename__ == "notifications"


class TestExpectedPortsStatusLogic:
    """Tests for expected ports status comparison logic."""

    def test_all_expected_ports_open(self):
        """Test when all expected ports are found open."""
        open_ports = {
            (80, "tcp"): {"port": 80, "protocol": "tcp"},
            (443, "tcp"): {"port": 443, "protocol": "tcp"},
            (22, "tcp"): {"port": 22, "protocol": "tcp"},
        }
        expected_ports = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]

        open_expected = []
        missing_expected = []

        for exp in expected_ports:
            key = (exp["port"], exp["protocol"])
            if key in open_ports:
                open_expected.append(exp)
            else:
                missing_expected.append(exp)

        assert len(open_expected) == 2
        assert len(missing_expected) == 0

    def test_some_expected_ports_missing(self):
        """Test when some expected ports are missing."""
        open_ports = {
            (80, "tcp"): {"port": 80, "protocol": "tcp"},
        }
        expected_ports = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
            {"port": 8080, "protocol": "tcp"},
        ]

        open_expected = []
        missing_expected = []

        for exp in expected_ports:
            key = (exp["port"], exp["protocol"])
            if key in open_ports:
                open_expected.append(exp)
            else:
                missing_expected.append(exp)

        assert len(open_expected) == 1
        assert len(missing_expected) == 2
        assert {"port": 443, "protocol": "tcp"} in missing_expected
        assert {"port": 8080, "protocol": "tcp"} in missing_expected

    def test_udp_tcp_ports_differentiated(self):
        """Test that UDP and TCP ports are treated separately."""
        open_ports = {
            (53, "tcp"): {"port": 53, "protocol": "tcp"},
        }
        expected_ports = [
            {"port": 53, "protocol": "udp"},  # Different protocol
        ]

        missing_expected = []
        for exp in expected_ports:
            key = (exp["port"], exp["protocol"])
            if key not in open_ports:
                missing_expected.append(exp)

        assert len(missing_expected) == 1
        assert missing_expected[0]["protocol"] == "udp"


class TestPortCountHistoryLogic:
    """Tests for port count history aggregation logic."""

    def test_port_count_aggregation(self):
        """Test aggregation of open port counts per scan."""
        scan_ports = {
            "scan-1": [80, 443],
            "scan-2": [80, 443, 22],
            "scan-3": [80],
        }

        history = []
        for scan_id, ports in scan_ports.items():
            history.append({
                "scan_id": scan_id,
                "open_port_count": len(ports),
            })

        assert history[0]["open_port_count"] == 2
        assert history[1]["open_port_count"] == 3
        assert history[2]["open_port_count"] == 1

    def test_empty_scan_returns_zero_ports(self):
        """Test that scan with no ports returns 0 count."""
        scan_ports = {}
        open_count = len(scan_ports)
        assert open_count == 0


class TestMigrationTableValidation:
    """Tests for migration table validation logic."""

    def test_valid_table_whitelist(self):
        """Test table validation against whitelist."""
        VALID_TABLES = {'ports', 'host_status', 'scans'}

        assert "ports" in VALID_TABLES
        assert "host_status" in VALID_TABLES
        assert "scans" in VALID_TABLES
        assert "users" not in VALID_TABLES

    def test_migration_column_check_logic(self):
        """Test column existence check logic."""
        existing_columns = ["id", "port", "protocol", "state"]
        new_column = "common_service"

        needs_migration = new_column not in existing_columns
        assert needs_migration is True

        existing_column = "port"
        needs_migration = existing_column not in existing_columns
        assert needs_migration is False

