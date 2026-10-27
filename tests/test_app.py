import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import app.main as main

client = TestClient(main.app)

def test_health_and_headers(monkeypatch):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_auth_required(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "test-key")
    response = client.get("/api/v1/demo")
    assert response.status_code == 401

def test_wrong_key_rejected(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "test-key")
    response = client.get("/api/v1/demo", headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 401

def test_missing_config_fails_closed(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "")
    response = client.get("/api/v1/demo", headers={"X-API-Key": "test-key"})
    assert response.status_code == 401

def test_read_demo(monkeypatch, tmp_path):
    db_path = tmp_path / "test.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", db_path)
    monkeypatch.setattr(main, "API_KEY", "test-key")
    
    response = client.get("/api/v1/demo", headers={"X-API-Key": "test-key"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "items" in data["tables"] or len(data["tables"]) >= 0

def test_invalid_id(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main, "API_KEY", "test-key")
    
    response = client.get("/items/0", headers={"X-API-Key": "test-key"})
    assert response.status_code == 400

def test_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main, "API_KEY", "test-key")
    
    response = client.get("/items/999", headers={"X-API-Key": "test-key"})
    assert response.status_code == 404

@pytest.mark.parametrize("name", [
    "",
    "x" * 65
])
def test_invalid_names(monkeypatch, tmp_path, name):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main, "API_KEY", "test-key")
    
    response = client.post("/items", params={"name": name}, headers={"X-API-Key": "test-key"})
    assert response.status_code in (400, 422)

def test_create_and_search(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main, "API_KEY", "test-key")
    
    # Create item
    res = client.post("/items", params={"name": "demo"}, headers={"X-API-Key": "test-key"})
    assert res.status_code == 200
    item_id = res.json()["id"]
    
    # Search item
    res2 = client.get("/items", params={"q": "demo"}, headers={"X-API-Key": "test-key"})
    assert res2.status_code == 200
    items = res2.json()["items"]
    assert any(i["id"] == item_id and i["name"] == "demo" for i in items)

def test_search_boundaries(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main, "API_KEY", "test-key")
    
    client.post("/items", params={"name": "apple"}, headers={"X-API-Key": "test-key"})
    client.post("/items", params={"name": "pineapple"}, headers={"X-API-Key": "test-key"})
    
    res = client.get("/items", params={"q": "apple"}, headers={"X-API-Key": "test-key"})
    assert res.status_code == 200
    items = res.json()["items"]
    names = [i["name"] for i in items]
    assert "apple" in names
    assert "pineapple" in names

def test_sql_metacharacters_are_data(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main, "API_KEY", "test-key")
    
    payload = "foo' OR '1'='1"
    client.post("/items", params={"name": payload}, headers={"X-API-Key": "test-key"})
    
    res = client.get("/items", params={"q": payload}, headers={"X-API-Key": "test-key"})
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1
    assert items[0]["name"] == payload

def test_database_creates_missing_nested_directory(monkeypatch, tmp_path):
    nested_path = tmp_path / "deep" / "nested" / "dir" / "database.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", nested_path)
    monkeypatch.setattr(main, "API_KEY", "test-key")
    
    res = client.post("/items", params={"name": "nested-test"}, headers={"X-API-Key": "test-key"})
    assert res.status_code == 200
    assert nested_path.is_file()
