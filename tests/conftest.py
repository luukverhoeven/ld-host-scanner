"""Shared pytest fixtures."""

import os
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, patch

# Set test environment before importing app modules
os.environ.setdefault("TARGET_HOST", "test.example.com")
os.environ.setdefault(
    "DATA_DIR",
    str(Path(__file__).resolve().parents[1] / "data" / "test_data"),
)


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    with patch("src.config.settings") as mock:
        mock.target_host = "test.example.com"
        mock.scan_interval_hours = 2
        mock.smtp_host = None
        mock.smtp_configured = False
        mock.webhook_url = None
        mock.webhook_configured = False
        mock.expected_ports = None
        mock.expected_ports_list = []
        mock.rustscan_batch_size = 1000
        mock.rustscan_timeout = 3000
        mock.rustscan_ulimit = 5000
        yield mock


@pytest.fixture
def sample_ports():
    """Sample port scan results."""
    return [
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": ""},
        {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": ""},
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": ""},
    ]


@pytest.fixture
def sample_expected_ports():
    """Sample expected ports configuration."""
    return [
        {"port": 80, "protocol": "tcp"},
        {"port": 443, "protocol": "tcp"},
        {"port": 8080, "protocol": "tcp"},
    ]


@pytest.fixture
def mock_database():
    """Mock database operations."""
    with patch("src.storage.database.get_recent_scans", new_callable=AsyncMock) as mock_scans, \
         patch("src.storage.database.get_scan_by_id", new_callable=AsyncMock) as mock_scan, \
         patch("src.storage.database.get_current_status", new_callable=AsyncMock) as mock_status:
        mock_scans.return_value = []
        mock_scan.return_value = None
        mock_status.return_value = None
        yield {
            "get_recent_scans": mock_scans,
            "get_scan_by_id": mock_scan,
            "get_current_status": mock_status,
        }


@pytest.fixture
def test_client(mock_database):
    """Create FastAPI test client with mocked dependencies."""
    from fastapi.testclient import TestClient

    # Mock scheduler before importing app
    with patch("src.scheduler.job_scheduler.get_scheduler") as mock_scheduler:
        mock_scheduler.return_value = None

        # Import app after mocking
        from src.web.app import app

        with TestClient(app) as client:
            yield client
