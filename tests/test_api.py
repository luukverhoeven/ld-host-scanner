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
         patch("src.storage.database.get_current_status", new_callable=AsyncMock) as mock_status:

        # Configure mocks
        mock_scheduler.return_value = None
        mock_scans.return_value = []
        mock_scan.return_value = None
        mock_status.return_value = None

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
        # Scheduler is mocked as None, so should be degraded
        assert data["status"] == "degraded"
        assert data["scheduler_running"] is False

    def test_liveness(self, client):
        """Test GET /live returns ok."""
        response = client.get("/live")

        assert response.status_code == 200
        data = response.json()
        assert data["alive"] is True
