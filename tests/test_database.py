"""Tests for async database operations."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import pytest

from src.storage.models import Scan, Port, PortChange, HostStatus, HostStatusHistory, Notification


@pytest.fixture
def mock_session():
    """Create mock AsyncSession with context manager support."""
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.add = AsyncMock()
    return session


@pytest.fixture
def mock_get_session(mock_session):
    """Mock get_session() to return mock_session."""
    async def _get_session():
        return mock_session

    with patch('src.storage.database.get_session', _get_session):
        yield mock_session


class TestSaveScan:
    """Tests for save_scan function."""

    @pytest.mark.asyncio
    async def test_save_scan_creates_new(self, mock_get_session):
        """Test creating a new scan record."""
        from src.storage.database import save_scan

        # Mock: scan doesn't exist
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        result = await save_scan(
            scan_id="test-scan-123",
            target="example.com",
            scan_type="full",
            started_at=datetime(2025, 1, 1, 12, 0, 0),
            status="running",
        )

        mock_get_session.add.assert_called_once()
        mock_get_session.commit.assert_awaited_once()
        # Returns the new scan object
        assert result is not None

    @pytest.mark.asyncio
    async def test_save_scan_updates_existing(self, mock_get_session):
        """Test updating an existing scan record."""
        from src.storage.database import save_scan

        # Mock: scan exists
        existing_scan = MagicMock(spec=Scan)
        existing_scan.status = "running"
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_scan
        mock_get_session.execute.return_value = mock_result

        result = await save_scan(
            scan_id="test-scan-123",
            target="example.com",
            scan_type="full",
            started_at=datetime(2025, 1, 1, 12, 0, 0),
            status="completed",
            host_status="up",
            completed_at=datetime(2025, 1, 1, 12, 30, 0),
        )

        # Should NOT add (updating existing)
        mock_get_session.add.assert_not_called()
        mock_get_session.commit.assert_awaited_once()
        # Check updates were applied
        assert existing_scan.status == "completed"
        assert existing_scan.host_status == "up"

    @pytest.mark.asyncio
    async def test_save_scan_with_error(self, mock_get_session):
        """Test saving a failed scan with error message."""
        from src.storage.database import save_scan

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        await save_scan(
            scan_id="test-scan-fail",
            target="example.com",
            scan_type="full",
            started_at=datetime(2025, 1, 1, 12, 0, 0),
            status="failed",
            error_message="Connection timeout",
        )

        mock_get_session.add.assert_called_once()
        added_scan = mock_get_session.add.call_args[0][0]
        assert added_scan.error_message == "Connection timeout"


class TestSavePorts:
    """Tests for save_ports function."""

    @pytest.mark.asyncio
    async def test_save_ports_bulk_insert(self, mock_get_session):
        """Test bulk port insertion."""
        from src.storage.database import save_ports

        ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
        ]

        await save_ports("test-scan-123", ports)

        mock_get_session.execute.assert_awaited_once()
        mock_get_session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_save_ports_empty_list(self, mock_get_session):
        """Test save_ports returns early for empty list."""
        from src.storage.database import save_ports

        await save_ports("test-scan-123", [])

        # Should not call execute or commit
        mock_get_session.execute.assert_not_awaited()
        mock_get_session.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_save_ports_with_stealth_flag(self, mock_get_session):
        """Test saving ports with stealth flag."""
        from src.storage.database import save_ports

        ports = [
            {"port": 51820, "protocol": "udp", "state": "open", "service": "wireguard", "is_stealth": True},
        ]

        await save_ports("test-scan-123", ports)

        mock_get_session.execute.assert_awaited_once()


class TestDetectChanges:
    """Tests for detect_changes function."""

    @pytest.mark.asyncio
    async def test_detect_changes_first_scan(self, mock_get_session):
        """Test no changes detected on first scan (no previous scan)."""
        from src.storage.database import detect_changes

        # Current ports
        current_port = MagicMock(spec=Port)
        current_port.port = 80
        current_port.protocol = "tcp"
        current_port.state = "open"
        current_port.service = "http"

        current_result = MagicMock()
        current_result.scalars.return_value.all.return_value = [current_port]

        # No previous scan
        prev_scan_result = MagicMock()
        prev_scan_result.scalar_one_or_none.return_value = None

        mock_get_session.execute.side_effect = [current_result, prev_scan_result]

        changes = await detect_changes("scan-123", "example.com")

        assert changes == []

    @pytest.mark.asyncio
    async def test_detect_changes_new_port_opened(self, mock_get_session):
        """Test detecting newly opened port."""
        from src.storage.database import detect_changes

        # Current ports: 80 and 443
        port_80 = MagicMock(spec=Port)
        port_80.port = 80
        port_80.protocol = "tcp"
        port_80.state = "open"
        port_80.service = "http"

        port_443 = MagicMock(spec=Port)
        port_443.port = 443
        port_443.protocol = "tcp"
        port_443.state = "open"
        port_443.service = "https"

        current_result = MagicMock()
        current_result.scalars.return_value.all.return_value = [port_80, port_443]

        # Previous scan exists
        prev_scan = MagicMock(spec=Scan)
        prev_scan.scan_id = "prev-scan"
        prev_scan_result = MagicMock()
        prev_scan_result.scalar_one_or_none.return_value = prev_scan

        # Previous ports: only 80
        prev_port_80 = MagicMock(spec=Port)
        prev_port_80.port = 80
        prev_port_80.protocol = "tcp"
        prev_port_80.state = "open"
        prev_port_80.service = "http"

        prev_ports_result = MagicMock()
        prev_ports_result.scalars.return_value.all.return_value = [prev_port_80]

        mock_get_session.execute.side_effect = [current_result, prev_scan_result, prev_ports_result]

        changes = await detect_changes("scan-123", "example.com")

        assert len(changes) == 1
        assert changes[0]["port"] == 443
        assert changes[0]["change_type"] == "opened"
        mock_get_session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_detect_changes_port_closed(self, mock_get_session):
        """Test detecting closed port."""
        from src.storage.database import detect_changes

        # Current ports: only 80
        port_80 = MagicMock(spec=Port)
        port_80.port = 80
        port_80.protocol = "tcp"
        port_80.state = "open"
        port_80.service = "http"

        current_result = MagicMock()
        current_result.scalars.return_value.all.return_value = [port_80]

        # Previous scan
        prev_scan = MagicMock(spec=Scan)
        prev_scan.scan_id = "prev-scan"
        prev_scan_result = MagicMock()
        prev_scan_result.scalar_one_or_none.return_value = prev_scan

        # Previous ports: 80 and 443
        prev_port_80 = MagicMock(spec=Port)
        prev_port_80.port = 80
        prev_port_80.protocol = "tcp"
        prev_port_80.state = "open"
        prev_port_80.service = "http"

        prev_port_443 = MagicMock(spec=Port)
        prev_port_443.port = 443
        prev_port_443.protocol = "tcp"
        prev_port_443.state = "open"
        prev_port_443.service = "https"

        prev_ports_result = MagicMock()
        prev_ports_result.scalars.return_value.all.return_value = [prev_port_80, prev_port_443]

        mock_get_session.execute.side_effect = [current_result, prev_scan_result, prev_ports_result]

        changes = await detect_changes("scan-123", "example.com")

        assert len(changes) == 1
        assert changes[0]["port"] == 443
        assert changes[0]["change_type"] == "closed"

    @pytest.mark.asyncio
    async def test_detect_changes_no_changes(self, mock_get_session):
        """Test no changes when ports are the same."""
        from src.storage.database import detect_changes

        # Current ports: 80
        port_80 = MagicMock(spec=Port)
        port_80.port = 80
        port_80.protocol = "tcp"
        port_80.state = "open"
        port_80.service = "http"

        current_result = MagicMock()
        current_result.scalars.return_value.all.return_value = [port_80]

        # Previous scan
        prev_scan = MagicMock(spec=Scan)
        prev_scan.scan_id = "prev-scan"
        prev_scan_result = MagicMock()
        prev_scan_result.scalar_one_or_none.return_value = prev_scan

        # Previous ports: also 80
        prev_port_80 = MagicMock(spec=Port)
        prev_port_80.port = 80
        prev_port_80.protocol = "tcp"
        prev_port_80.state = "open"
        prev_port_80.service = "http"

        prev_ports_result = MagicMock()
        prev_ports_result.scalars.return_value.all.return_value = [prev_port_80]

        mock_get_session.execute.side_effect = [current_result, prev_scan_result, prev_ports_result]

        changes = await detect_changes("scan-123", "example.com")

        assert changes == []


class TestGetRecentScans:
    """Tests for get_recent_scans function."""

    @pytest.mark.asyncio
    async def test_get_recent_scans_empty(self, mock_get_session):
        """Test get_recent_scans with no scans."""
        from src.storage.database import get_recent_scans

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_get_session.execute.return_value = mock_result

        result = await get_recent_scans()

        assert result == []

    @pytest.mark.asyncio
    async def test_get_recent_scans_with_data(self, mock_get_session):
        """Test get_recent_scans returns formatted data."""
        from src.storage.database import get_recent_scans

        # Mock scan
        scan = MagicMock(spec=Scan)
        scan.scan_id = "scan-123"
        scan.target = "example.com"
        scan.scan_type = "full"
        scan.status = "completed"
        scan.host_status = "up"
        scan.started_at = datetime(2025, 1, 1, 12, 0, 0)
        scan.completed_at = datetime(2025, 1, 1, 12, 30, 0)
        scan.error_message = None

        scans_result = MagicMock()
        scans_result.scalars.return_value.all.return_value = [scan]

        # Mock port
        port = MagicMock(spec=Port)
        port.scan_id = "scan-123"
        port.port = 80
        port.protocol = "tcp"
        port.state = "open"
        port.service = "http"
        port.version = "Apache/2.4"
        port.common_service = "http"
        port.is_stealth = False

        ports_result = MagicMock()
        ports_result.scalars.return_value.all.return_value = [port]

        mock_get_session.execute.side_effect = [scans_result, ports_result]

        result = await get_recent_scans(limit=10)

        assert len(result) == 1
        assert result[0]["scan_id"] == "scan-123"
        assert result[0]["target"] == "example.com"
        assert len(result[0]["ports"]) == 1
        assert result[0]["ports"][0]["port"] == 80

    @pytest.mark.asyncio
    async def test_get_recent_scans_pagination(self, mock_get_session):
        """Test get_recent_scans with pagination."""
        from src.storage.database import get_recent_scans

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_get_session.execute.return_value = mock_result

        await get_recent_scans(limit=5, offset=10)

        # Verify execute was called (pagination is in query)
        mock_get_session.execute.assert_awaited()


class TestGetScanById:
    """Tests for get_scan_by_id function."""

    @pytest.mark.asyncio
    async def test_get_scan_by_id_not_found(self, mock_get_session):
        """Test get_scan_by_id returns None for missing scan."""
        from src.storage.database import get_scan_by_id

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        result = await get_scan_by_id("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_scan_by_id_found(self, mock_get_session):
        """Test get_scan_by_id returns scan with ports and changes."""
        from src.storage.database import get_scan_by_id

        # Mock scan
        scan = MagicMock(spec=Scan)
        scan.scan_id = "scan-123"
        scan.target = "example.com"
        scan.scan_type = "full"
        scan.status = "completed"
        scan.host_status = "up"
        scan.started_at = datetime(2025, 1, 1, 12, 0, 0)
        scan.completed_at = datetime(2025, 1, 1, 12, 30, 0)
        scan.error_message = None

        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = scan

        # Mock port
        port = MagicMock(spec=Port)
        port.port = 80
        port.protocol = "tcp"
        port.state = "open"
        port.service = "http"
        port.version = None
        port.common_service = "http"
        port.is_stealth = False

        ports_result = MagicMock()
        ports_result.scalars.return_value.all.return_value = [port]

        # Mock change
        change = MagicMock(spec=PortChange)
        change.port = 443
        change.protocol = "tcp"
        change.change_type = "opened"
        change.service = "https"

        changes_result = MagicMock()
        changes_result.scalars.return_value.all.return_value = [change]

        mock_get_session.execute.side_effect = [scan_result, ports_result, changes_result]

        result = await get_scan_by_id("scan-123")

        assert result["scan_id"] == "scan-123"
        assert len(result["ports"]) == 1
        assert len(result["changes"]) == 1
        assert result["changes"][0]["port"] == 443


class TestSaveHostStatus:
    """Tests for save_host_status function."""

    @pytest.mark.asyncio
    async def test_save_host_status_new_online(self, mock_get_session):
        """Test creating new host status as online."""
        from src.storage.database import save_host_status

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        failure_count = await save_host_status("example.com", "online")

        assert failure_count == 0
        mock_get_session.add.assert_called_once()
        mock_get_session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_save_host_status_new_offline(self, mock_get_session):
        """Test creating new host status as offline."""
        from src.storage.database import save_host_status

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        failure_count = await save_host_status("example.com", "offline")

        assert failure_count == 1

    @pytest.mark.asyncio
    async def test_save_host_status_update_increments_failure(self, mock_get_session):
        """Test updating existing status increments failure count."""
        from src.storage.database import save_host_status

        existing_status = MagicMock(spec=HostStatus)
        existing_status.failure_count = 2

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_status
        mock_get_session.execute.return_value = mock_result

        failure_count = await save_host_status("example.com", "offline")

        assert failure_count == 3
        assert existing_status.failure_count == 3

    @pytest.mark.asyncio
    async def test_save_host_status_online_resets_failure(self, mock_get_session):
        """Test online status resets failure count to 0."""
        from src.storage.database import save_host_status

        existing_status = MagicMock(spec=HostStatus)
        existing_status.failure_count = 5

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_status
        mock_get_session.execute.return_value = mock_result

        failure_count = await save_host_status("example.com", "online")

        assert failure_count == 0
        assert existing_status.failure_count == 0


class TestGetCurrentStatus:
    """Tests for get_current_status function."""

    @pytest.mark.asyncio
    async def test_get_current_status_no_data(self, mock_get_session):
        """Test get_current_status returns None when no data."""
        from src.storage.database import get_current_status

        host_result = MagicMock()
        host_result.scalar_one_or_none.return_value = None

        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = None

        mock_get_session.execute.side_effect = [host_result, scan_result]

        result = await get_current_status("example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_current_status_prefers_host_status(self, mock_get_session):
        """Test get_current_status prefers real-time host status over scan."""
        from src.storage.database import get_current_status

        # Real-time host status
        host_status = MagicMock(spec=HostStatus)
        host_status.status = "online"
        host_status.last_check = datetime(2025, 1, 1, 12, 0, 0)

        host_result = MagicMock()
        host_result.scalar_one_or_none.return_value = host_status

        # Scan (older)
        scan = MagicMock(spec=Scan)
        scan.scan_id = "scan-123"
        scan.host_status = "down"  # Different from real-time
        scan.completed_at = datetime(2025, 1, 1, 11, 0, 0)

        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = scan

        # No ports query needed in this path
        ports_result = MagicMock()
        ports_result.scalars.return_value.all.return_value = []

        mock_get_session.execute.side_effect = [host_result, scan_result, ports_result]

        result = await get_current_status("example.com")

        assert result["host_status"] == "up"  # From real-time check (online -> up)


class TestGetPortCountHistory:
    """Tests for get_port_count_history function."""

    @pytest.mark.asyncio
    async def test_get_port_count_history_empty(self, mock_get_session):
        """Test get_port_count_history with no scans."""
        from src.storage.database import get_port_count_history

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_get_session.execute.return_value = mock_result

        result = await get_port_count_history("example.com")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_port_count_history_with_data(self, mock_get_session):
        """Test get_port_count_history returns chronological data."""
        from src.storage.database import get_port_count_history

        # Mock scans
        scan1 = MagicMock(spec=Scan)
        scan1.scan_id = "scan-1"
        scan1.completed_at = datetime(2025, 1, 1, 10, 0, 0)
        scan1.host_status = "up"

        scan2 = MagicMock(spec=Scan)
        scan2.scan_id = "scan-2"
        scan2.completed_at = datetime(2025, 1, 1, 12, 0, 0)
        scan2.host_status = "up"

        scans_result = MagicMock()
        scans_result.scalars.return_value.all.return_value = [scan2, scan1]  # DESC order

        # Mock port counts
        counts_result = MagicMock()
        counts_result.all.return_value = [("scan-1", 3), ("scan-2", 5)]

        mock_get_session.execute.side_effect = [scans_result, counts_result]

        result = await get_port_count_history("example.com", limit=10)

        # Should be reversed to chronological order
        assert len(result) == 2
        assert result[0]["open_port_count"] == 3  # scan-1 (older)
        assert result[1]["open_port_count"] == 5  # scan-2 (newer)


class TestGetHostStatusHistory:
    """Tests for get_host_status_history function."""

    @pytest.mark.asyncio
    async def test_get_host_status_history_empty(self, mock_get_session):
        """Test get_host_status_history with no records."""
        from src.storage.database import get_host_status_history

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_get_session.execute.return_value = mock_result

        result = await get_host_status_history("example.com")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_host_status_history_returns_chronological(self, mock_get_session):
        """Test get_host_status_history returns data in chronological order."""
        from src.storage.database import get_host_status_history

        # Mock records (returned in DESC order from DB)
        record1 = MagicMock(spec=HostStatusHistory)
        record1.checked_at = datetime(2025, 1, 1, 12, 0, 0)
        record1.status = "online"
        record1.dns_resolved = True
        record1.tcp_reachable = True
        record1.check_method = "icmp"

        record2 = MagicMock(spec=HostStatusHistory)
        record2.checked_at = datetime(2025, 1, 1, 11, 0, 0)
        record2.status = "online"
        record2.dns_resolved = True
        record2.tcp_reachable = False
        record2.check_method = "tcp"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [record1, record2]  # DESC
        mock_get_session.execute.return_value = mock_result

        result = await get_host_status_history("example.com", limit=10)

        # Should be reversed to chronological (oldest first)
        assert len(result) == 2
        assert result[0]["check_method"] == "tcp"  # 11:00 (older)
        assert result[1]["check_method"] == "icmp"  # 12:00 (newer)


class TestSaveHostStatusHistory:
    """Tests for save_host_status_history function."""

    @pytest.mark.asyncio
    async def test_save_host_status_history(self, mock_get_session):
        """Test saving host status history record."""
        from src.storage.database import save_host_status_history

        await save_host_status_history(
            target="example.com",
            status="online",
            dns_resolved=True,
            tcp_reachable=True,
            icmp_reachable=True,
            check_method="icmp",
        )

        mock_get_session.add.assert_called_once()
        mock_get_session.commit.assert_awaited_once()


class TestGetOpenPortsFromLastScan:
    """Tests for get_open_ports_from_last_scan function."""

    @pytest.mark.asyncio
    async def test_get_open_ports_no_scan(self, mock_get_session):
        """Test returns empty list when no scan exists."""
        from src.storage.database import get_open_ports_from_last_scan

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        result = await get_open_ports_from_last_scan("example.com")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_open_ports_returns_tcp_ports(self, mock_get_session):
        """Test returns list of open TCP port numbers."""
        from src.storage.database import get_open_ports_from_last_scan

        # Mock scan
        scan = MagicMock(spec=Scan)
        scan.scan_id = "scan-123"

        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = scan

        # Mock ports
        port1 = MagicMock(spec=Port)
        port1.port = 80

        port2 = MagicMock(spec=Port)
        port2.port = 443

        ports_result = MagicMock()
        ports_result.scalars.return_value.all.return_value = [port1, port2]

        mock_get_session.execute.side_effect = [scan_result, ports_result]

        result = await get_open_ports_from_last_scan("example.com")

        assert result == [80, 443]


class TestSaveNotification:
    """Tests for save_notification function."""

    @pytest.mark.asyncio
    async def test_save_notification_success(self, mock_get_session):
        """Test saving notification record."""
        from src.storage.database import save_notification

        await save_notification(
            notification_type="email",
            status="sent",
            scan_id="scan-123",
            subject="Port change alert",
            message="Port 443 opened",
        )

        mock_get_session.add.assert_called_once()
        mock_get_session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_save_notification_failed(self, mock_get_session):
        """Test saving failed notification record."""
        from src.storage.database import save_notification

        await save_notification(
            notification_type="webhook",
            status="failed",
            error_message="Connection refused",
        )

        mock_get_session.add.assert_called_once()


class TestUpdateScanProgress:
    """Tests for update_scan_progress function."""

    @pytest.mark.asyncio
    async def test_update_scan_progress_found(self, mock_get_session):
        """Test updating scan progress when scan exists."""
        from src.storage.database import update_scan_progress

        scan = MagicMock(spec=Scan)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = scan
        mock_get_session.execute.return_value = mock_result

        await update_scan_progress(
            scan_id="scan-123",
            current_phase="tcp_scan",
            tcp_ports_found=10,
            udp_ports_found=2,
        )

        assert scan.current_phase == "tcp_scan"
        assert scan.tcp_ports_found == 10
        assert scan.udp_ports_found == 2
        mock_get_session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_scan_progress_not_found(self, mock_get_session):
        """Test update_scan_progress does nothing when scan not found."""
        from src.storage.database import update_scan_progress

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        await update_scan_progress("nonexistent", "tcp_scan")

        # Should not commit if scan not found
        mock_get_session.commit.assert_not_awaited()


class TestGetPortHistory:
    """Tests for get_port_history function."""

    @pytest.mark.asyncio
    async def test_get_port_history(self, mock_get_session):
        """Test getting port change history."""
        from src.storage.database import get_port_history

        change = MagicMock(spec=PortChange)
        change.scan_id = "scan-123"
        change.port = 443
        change.protocol = "tcp"
        change.change_type = "opened"
        change.service = "https"
        change.detected_at = datetime(2025, 1, 1, 12, 0, 0)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [change]
        mock_get_session.execute.return_value = mock_result

        result = await get_port_history(limit=50)

        assert len(result) == 1
        assert result[0]["port"] == 443
        assert result[0]["change_type"] == "opened"


class TestGetChangesForScan:
    """Tests for get_changes_for_scan function."""

    @pytest.mark.asyncio
    async def test_get_changes_for_scan(self, mock_get_session):
        """Test getting changes for a specific scan."""
        from src.storage.database import get_changes_for_scan

        change = MagicMock(spec=PortChange)
        change.port = 22
        change.protocol = "tcp"
        change.change_type = "closed"
        change.service = "ssh"
        change.detected_at = datetime(2025, 1, 1, 12, 0, 0)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [change]
        mock_get_session.execute.return_value = mock_result

        result = await get_changes_for_scan("scan-123")

        assert len(result) == 1
        assert result[0]["port"] == 22
        assert result[0]["change_type"] == "closed"


class TestGetExpectedPortsStatus:
    """Tests for get_expected_ports_status function."""

    @pytest.mark.asyncio
    async def test_get_expected_ports_status_no_scan(self, mock_get_session):
        """Test expected ports status when no scan exists."""
        from src.storage.database import get_expected_ports_status

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        expected_ports = [{"port": 80, "protocol": "tcp"}]
        result = await get_expected_ports_status("example.com", expected_ports)

        assert result["configured"] is True
        assert result["all_open"] is None
        assert len(result["missing_ports"]) == 1

    @pytest.mark.asyncio
    async def test_get_expected_ports_status_all_open(self, mock_get_session):
        """Test expected ports status when all ports are open."""
        from src.storage.database import get_expected_ports_status

        # Mock scan
        scan = MagicMock(spec=Scan)
        scan.scan_id = "scan-123"
        scan.completed_at = datetime(2025, 1, 1, 12, 0, 0)

        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = scan

        # Mock ports - both expected ports are open
        port_80 = MagicMock(spec=Port)
        port_80.port = 80
        port_80.protocol = "tcp"
        port_80.service = "http"

        port_443 = MagicMock(spec=Port)
        port_443.port = 443
        port_443.protocol = "tcp"
        port_443.service = "https"

        ports_result = MagicMock()
        ports_result.scalars.return_value.all.return_value = [port_80, port_443]

        mock_get_session.execute.side_effect = [scan_result, ports_result]

        expected_ports = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]
        result = await get_expected_ports_status("example.com", expected_ports)

        assert result["all_open"] is True
        assert len(result["open_ports"]) == 2
        assert len(result["missing_ports"]) == 0


class TestUpdatePortService:
    """Tests for update_port_service function."""

    @pytest.mark.asyncio
    async def test_update_port_service_success(self, mock_get_session):
        """Test successfully updating port service info."""
        from src.storage.database import update_port_service

        # Mock scan
        scan = MagicMock(spec=Scan)
        scan.scan_id = "scan-123"

        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = scan

        # Mock port
        port = MagicMock(spec=Port)
        port_result = MagicMock()
        port_result.scalar_one_or_none.return_value = port

        mock_get_session.execute.side_effect = [scan_result, port_result]

        result = await update_port_service(
            target="example.com",
            port_num=80,
            protocol="tcp",
            service="http",
            version="Apache/2.4",
            common_service="http",
        )

        assert result is True
        assert port.service == "http"
        assert port.version == "Apache/2.4"
        mock_get_session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_port_service_no_scan(self, mock_get_session):
        """Test update_port_service returns False when no scan."""
        from src.storage.database import update_port_service

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        result = await update_port_service(
            target="example.com",
            port_num=80,
            protocol="tcp",
            service="http",
            version=None,
            common_service=None,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_update_port_service_port_not_found(self, mock_get_session):
        """Test update_port_service returns False when port not found."""
        from src.storage.database import update_port_service

        # Scan exists
        scan = MagicMock(spec=Scan)
        scan.scan_id = "scan-123"
        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = scan

        # Port not found
        port_result = MagicMock()
        port_result.scalar_one_or_none.return_value = None

        mock_get_session.execute.side_effect = [scan_result, port_result]

        result = await update_port_service(
            target="example.com",
            port_num=9999,
            protocol="tcp",
            service=None,
            version=None,
            common_service=None,
        )

        assert result is False


class TestGetLastHostStatus:
    """Tests for get_last_host_status function."""

    @pytest.mark.asyncio
    async def test_get_last_host_status_exists(self, mock_get_session):
        """Test getting last host status when record exists."""
        from src.storage.database import get_last_host_status

        host_status = MagicMock(spec=HostStatus)
        host_status.status = "online"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = host_status
        mock_get_session.execute.return_value = mock_result

        result = await get_last_host_status("example.com")

        assert result == "online"

    @pytest.mark.asyncio
    async def test_get_last_host_status_not_exists(self, mock_get_session):
        """Test getting last host status when no record."""
        from src.storage.database import get_last_host_status

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        result = await get_last_host_status("example.com")

        assert result is None


class TestGetHostStatusRecord:
    """Tests for get_host_status_record function."""

    @pytest.mark.asyncio
    async def test_get_host_status_record_exists(self, mock_get_session):
        """Test getting full host status record."""
        from src.storage.database import get_host_status_record

        host_status = MagicMock(spec=HostStatus)
        host_status.target = "example.com"
        host_status.status = "online"
        host_status.failure_count = 0
        host_status.last_check = datetime(2025, 1, 1, 12, 0, 0)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = host_status
        mock_get_session.execute.return_value = mock_result

        result = await get_host_status_record("example.com")

        assert result["target"] == "example.com"
        assert result["status"] == "online"
        assert result["failure_count"] == 0

    @pytest.mark.asyncio
    async def test_get_host_status_record_not_exists(self, mock_get_session):
        """Test getting host status record when none exists."""
        from src.storage.database import get_host_status_record

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        result = await get_host_status_record("example.com")

        assert result is None


class TestGetPreviousMissingExpectedPorts:
    """Tests for get_previous_missing_expected_ports function."""

    @pytest.mark.asyncio
    async def test_no_previous_scan(self, mock_get_session):
        """Test returns empty list when no previous scan."""
        from src.storage.database import get_previous_missing_expected_ports

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_get_session.execute.return_value = mock_result

        result = await get_previous_missing_expected_ports(
            "example.com",
            "current-scan",
            [{"port": 80, "protocol": "tcp"}],
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_with_previous_missing_ports(self, mock_get_session):
        """Test returns ports that were missing in previous scan."""
        from src.storage.database import get_previous_missing_expected_ports

        # Previous scan exists
        prev_scan = MagicMock(spec=Scan)
        prev_scan.scan_id = "prev-scan"

        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = prev_scan

        # Only port 80 was open in previous scan (443 was missing)
        port = MagicMock(spec=Port)
        port.port = 80
        port.protocol = "tcp"

        ports_result = MagicMock()
        ports_result.scalars.return_value.all.return_value = [port]

        mock_get_session.execute.side_effect = [scan_result, ports_result]

        expected_ports = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
        ]
        result = await get_previous_missing_expected_ports(
            "example.com",
            "current-scan",
            expected_ports,
        )

        # Port 443 was missing in previous scan
        assert len(result) == 1
        assert result[0]["port"] == 443
