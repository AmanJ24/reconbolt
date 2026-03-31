"""Tests for the FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient

from reconbolt.api.app import app


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


class TestHealthEndpoint:
    """Tests for the health check endpoint."""

    def test_health_check(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "reconbolt"
        assert "version" in data


class TestScanEndpoints:
    """Tests for the scan CRUD endpoints."""

    def test_list_scans_empty(self, client):
        response = client.get("/api/scans/")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_get_nonexistent_scan(self, client):
        response = client.get("/api/scans/nonexistent")
        assert response.status_code == 404

    def test_delete_nonexistent_scan(self, client):
        response = client.delete("/api/scans/nonexistent")
        assert response.status_code == 404

    def test_start_scan(self, client):
        response = client.post(
            "/api/scans/",
            json={
                "target": "example.com",
                "intensity": "low",
                "enable_port_scan": False,
                "enable_vuln_scan": False,
                "enable_osint": False,
                "enable_ai_analysis": False,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["target"] == "example.com"
        assert data["status"] == "running"
