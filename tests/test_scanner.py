import pytest
from fastapi.testclient import TestClient
import app.main as main

client = TestClient(main.app)

def test_orchestrator_invalid_directory(tmp_path):
    from app.scanner.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator()
    invalid_dir = tmp_path / "nonexistent"
    result = orchestrator.run_scan(invalid_dir)
    assert "error" in result or result.get("findings", []) == []

def test_scan_endpoint_unauthorized(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret-key")
    response = client.post("/api/v1/scan", json={"target_path": "."})
    assert response.status_code == 401

def test_scan_endpoint_path_traversal(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret-key")
    # Attempt parent directory traversal
    response = client.post(
        "/api/v1/scan",
        json={"target_path": "../etc"},
        headers={"X-API-Key": "secret-key"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Path traversal detected."

def test_scan_endpoint_sibling_prefix_bypass(monkeypatch):
    """
    Regression test for string-prefix containment flaw (e.g. /workspace-evil).
    Verifies that is_relative_to correctly blocks sibling directory prefix matches.
    """
    monkeypatch.setattr(main, "API_KEY", "secret-key")
    response = client.post(
        "/api/v1/scan",
        json={"target_path": "../CodeAlpha_SecureCodeReview-evil"},
        headers={"X-API-Key": "secret-key"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Path traversal detected."

def test_scan_endpoint_success(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "API_KEY", "secret-key")
    # Scan a safe temporary directory inside workspace bounds
    response = client.post(
        "/api/v1/scan",
        json={"target_path": "."},
        headers={"X-API-Key": "secret-key"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "findings" in data
    assert "summary" in data
