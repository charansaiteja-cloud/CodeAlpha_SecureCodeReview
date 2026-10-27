import os
import pytest
from fastapi.testclient import TestClient
import app.main as main

client = TestClient(main.app)

def test_health_and_headers():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
    # Verify security headers middleware
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"

def test_auth_required(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret123")
    response = client.get("/api/v1/demo")
    assert response.status_code == 401

def test_wrong_key_rejected(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret123")
    response = client.get("/api/v1/demo", headers={"X-API-Key": "wrongkey"})
    assert response.status_code == 401

def test_missing_config_fails_closed(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "")
    response = client.get("/api/v1/demo", headers={"X-API-Key": "anykey"})
    assert response.status_code == 401

def test_read_demo(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret123")
    response = client.get("/api/v1/demo", headers={"X-API-Key": "secret123"})
    assert response.status_code == 200
    assert "tables" in response.json()

def test_invalid_id(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret123")
    response = client.get("/items/0", headers={"X-API-Key": "secret123"})
    assert response.status_code == 400

def test_not_found(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret123")
    response = client.get("/items/99999", headers={"X-API-Key": "secret123"})
    assert response.status_code == 404

@pytest.mark.parametrize("name", ["", "x" * 65])
def test_invalid_names(monkeypatch, name):
    monkeypatch.setattr(main, "API_KEY", "secret123")
    response = client.post(
        "/items",
        json={"name": name},
        headers={"X-API-Key": "secret123"}
    )
    # Pydantic validates min_length=1 and max_length=64 returning 422
    assert response.status_code in (400, 422)

def test_create_and_search(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret123")
    # Create item via JSON body
    res = client.post(
        "/items",
        json={"name": "AlphaSecurityItem"},
        headers={"X-API-Key": "secret123"}
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "AlphaSecurityItem"
    assert "id" in data

    # Search items
    res2 = client.get(
        "/items?q=AlphaSecurity",
        headers={"X-API-Key": "secret123"}
    )
    assert res2.status_code == 200
    items = res2.json().get("items", [])
    assert any(i["name"] == "AlphaSecurityItem" for i in items)

def test_search_boundaries(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret123")
    res = client.get(
        "/items?q=nonexistentitemxyz123",
        headers={"X-API-Key": "secret123"}
    )
    assert res.status_code == 200
    assert res.json().get("items") == []

def test_sql_metacharacters_are_data(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret123")
    malicious_input = "' OR '1'='1"
    res = client.post(
        "/items",
        json={"name": malicious_input},
        headers={"X-API-Key": "secret123"}
    )
    assert res.status_code == 201

    # Search using metacharacters should treat them literally as data due to parameterization
    res2 = client.get(
        f"/items?q={malicious_input}",
        headers={"X-API-Key": "secret123"}
    )
    assert res2.status_code == 200
    items = res2.json().get("items", [])
    assert len(items) == 1
    assert items[0]["name"] == malicious_input

def test_database_creates_missing_nested_directory(monkeypatch, tmp_path):
    nested_db = tmp_path / "deep" / "nested" / "path" / "test.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", nested_db)
    monkeypatch.setattr(main, "API_KEY", "secret123")

    res = client.post(
        "/items",
        json={"name": "NestedDirTest"},
        headers={"X-API-Key": "secret123"}
    )
    assert res.status_code == 201
    assert nested_db.exists()
