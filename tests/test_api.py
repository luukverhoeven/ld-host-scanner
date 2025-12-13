"""Tests for API endpoints."""

import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create test client with mocked dependencies."""
    with patch("src.scheduler.job_scheduler.get_scheduler") as mock_scheduler, \
         patch("src.storage.database.get_recent_scans", new_callable=AsyncMock) as mock_scans, \
         patch("src.storage.database.get_scan_by_id", new_callable=AsyncMock) as mock_scan, \
         patch("src.storage.database.get_current_status", new_callable=AsyncMock) as mock_status, \
         patch("src.storage.database.get_port_count_history", new_callable=AsyncMock) as mock_port_history, \
         patch("src.storage.database.get_host_status_history", new_callable=AsyncMock) as mock_host_history:

        # Configure mocks
        mock_scheduler.return_value = None
        mock_scans.return_value = []
        mock_scan.return_value = None
        mock_status.return_value = None
        mock_port_history.return_value = []
        mock_host_history.return_value = []

        from src.web.app import app
        with TestClient(app) as test_client:
            yield test_client


class TestApiEndpoints:
    """Tests for REST API endpoints."""

    def test_list_scans_empty(self, client):
        """Test GET /api/scans returns empty list."""
        response = client.get("/api/scans")

        assert response.status_code == 200
        assert response.json() == []

    def test_get_scan_not_found(self, client):
        """Test GET /api/scans/{id} returns 404 for missing scan."""
        response = client.get("/api/scans/nonexistent-id")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_get_status(self, client):
        """Test GET /api/status returns valid structure."""
        response = client.get("/api/status")

        assert response.status_code == 200
        data = response.json()
        assert "target" in data
        assert "host_status" in data
        assert "open_port_count" in data
        assert "ports" in data

    def test_get_config(self, client):
        """Test GET /api/config returns config without secrets."""
        response = client.get("/api/config")

        assert response.status_code == 200
        data = response.json()
        assert "target_host" in data
        assert "scan_interval_hours" in data
        assert "smtp_configured" in data
        assert "webhook_configured" in data
        # Ensure no secrets are exposed
        assert "smtp_password" not in data
        assert "smtp_user" not in data


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_check(self, client):
        """Test GET /health returns status."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "scheduler_running" in data
        assert "version" in data
        # Scheduler is mocked as None, so should be degraded
        assert data["status"] == "degraded"
        assert data["scheduler_running"] is False

    def test_health_check_includes_version(self, client):
        """Test GET /health includes version info."""
        from src.version import __version__

        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["version"] == __version__

    def test_version_endpoint(self, client):
        """Test GET /version returns version info."""
        from src.version import __version__

        response = client.get("/version")

        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "build_date" in data
        assert "git_commit" in data
        assert data["version"] == __version__

    def test_liveness(self, client):
        """Test GET /live returns ok."""
        response = client.get("/live")

        assert response.status_code == 200
        data = response.json()
        assert data["alive"] is True

    def test_readiness_without_scheduler(self, client):
        """Test GET /ready returns not ready when scheduler is None."""
        response = client.get("/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is False
        assert "reason" in data


class TestHistoryEndpoints:
    """Tests for history API endpoints."""

    def test_port_history_empty(self, client):
        """Test GET /api/port-history returns empty list."""
        response = client.get("/api/port-history")

        assert response.status_code == 200
        assert response.json() == []

    def test_port_history_with_limit(self, client):
        """Test GET /api/port-history accepts limit parameter."""
        response = client.get("/api/port-history?limit=10")

        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_port_history_limit_validation(self, client):
        """Test GET /api/port-history validates limit range."""
        # Limit too low
        response = client.get("/api/port-history?limit=0")
        assert response.status_code == 422

        # Limit too high
        response = client.get("/api/port-history?limit=400")
        assert response.status_code == 422

    def test_host_status_history_empty(self, client):
        """Test GET /api/host-status-history returns empty list."""
        response = client.get("/api/host-status-history")

        assert response.status_code == 200
        assert response.json() == []

    def test_host_status_history_with_limit(self, client):
        """Test GET /api/host-status-history accepts limit parameter."""
        response = client.get("/api/host-status-history?limit=24")

        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_host_status_history_limit_validation(self, client):
        """Test GET /api/host-status-history validates limit range."""
        # Limit too low
        response = client.get("/api/host-status-history?limit=0")
        assert response.status_code == 422

        # Limit too high
        response = client.get("/api/host-status-history?limit=400")
        assert response.status_code == 422


class TestDashboardRoutes:
    """Tests for dashboard HTML routes."""

    def test_dashboard_home(self, client):
        """Test GET / returns dashboard HTML."""
        response = client.get("/")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_dashboard_home_contains_target(self, client):
        """Test dashboard home contains target host."""
        response = client.get("/")

        assert response.status_code == 200
        # Should contain target host somewhere in the page
        assert b"test.example.com" in response.content or b"target" in response.content.lower()

    def test_history_page(self, client):
        """Test GET /history returns history page HTML."""
        response = client.get("/history")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_history_page_with_limit(self, client):
        """Test GET /history accepts limit parameter."""
        response = client.get("/history?limit=50")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]


class TestScanDetailPage:
    """Tests for scan detail page."""

    def test_scan_detail_not_found(self, client):
        """Test GET /scan/{id} returns 404 for missing scan."""
        response = client.get("/scan/nonexistent-id")

        assert response.status_code == 404


class TestMetricsEndpoint:
    """Tests for Prometheus metrics endpoint."""

    def test_metrics_endpoint_exists(self, client):
        """Test GET /metrics returns prometheus metrics."""
        response = client.get("/metrics")

        assert response.status_code == 200
        # Prometheus format
        assert "text/plain" in response.headers["content-type"] or "text/plain" in str(response.content)


class TestApiListScansWithData:
    """Tests for scan listing with actual data."""

    def test_list_scans_with_limit(self, client):
        """Test GET /api/scans accepts limit parameter."""
        response = client.get("/api/scans?limit=5")

        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_list_scans_with_offset(self, client):
        """Test GET /api/scans accepts offset parameter."""
        response = client.get("/api/scans?offset=10")

        assert response.status_code == 200
        assert isinstance(response.json(), list)
