import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.scanner.orchestrator import ScanOrchestrator
from app.scanner.bandit_runner import BanditRunner
from app.scanner.semgrep_runner import SemgrepRunner

@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    monkeypatch.setattr("app.main.API_KEY", "test-master-key-secure-12345")

client = TestClient(app)

def test_orchestrator_invalid_directory():
    orchestrator = ScanOrchestrator()
    with pytest.raises(ValueError, match="Invalid target directory"):
        orchestrator.run_scan(Path("/nonexistent/path/12345"))

def test_scan_endpoint_unauthorized():
    response = client.post("/api/v1/scan", json={"target_path": "app"})
    assert response.status_code == 401

def test_scan_endpoint_path_traversal():
    response = client.post(
        "/api/v1/scan",
        headers={"X-API-Key": "test-master-key-secure-12345"},
        json={"target_path": "../"}
    )
    assert response.status_code == 400
    assert "Path traversal detected" in response.json()["detail"]

def test_scan_endpoint_success():
    response = client.post(
        "/api/v1/scan",
        headers={"X-API-Key": "test-master-key-secure-12345"},
        json={"target_path": "app"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "findings" in data
    assert "severity_breakdown" in data
