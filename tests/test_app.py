import pytest
from fastapi.testclient import TestClient
import app.main as main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr(main, "API_KEY", "test-key")
    with TestClient(main.app) as c:
        yield c


def auth():
    return {"X-API-Key": "test-key"}


def test_health_and_headers(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_auth_required(client):
    assert client.get("/items/1").status_code == 401


def test_wrong_key_rejected(client):
    assert client.get("/items/1", headers={"X-API-Key": "bad"}).status_code == 401


def test_missing_config_fails_closed(client, monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "")
    assert client.get("/items/1", headers=auth()).status_code == 401


def test_read_demo(client):
    r = client.get("/items/1", headers=auth())
    assert r.status_code == 200
    assert r.json()["name"] == "demo"


def test_invalid_id(client):
    assert client.get("/items/0", headers=auth()).status_code == 422


def test_not_found(client):
    assert client.get("/items/999", headers=auth()).status_code == 404


@pytest.mark.parametrize("name", ["", "x" * 81, "bad; DROP TABLE items"])
def test_invalid_names(client, name):
    assert client.post(
        "/items", json={"name": name}, headers=auth()
    ).status_code == 422


def test_create_and_search(client):
    r = client.post(
        "/items", json={"name": "secure demo"}, headers=auth()
    )
    assert r.status_code == 201
    r = client.get("/search", params={"q": "secure"}, headers=auth())
    assert r.status_code == 200
    assert any(x["name"] == "secure demo" for x in r.json()["items"])


def test_search_boundaries(client):
    assert client.get(
        "/search", params={"q": ""}, headers=auth()
    ).status_code == 422
    assert client.get(
        "/search", params={"q": "a" * 81}, headers=auth()
    ).status_code == 422


def test_sql_metacharacters_are_data(client):
    r = client.get(
        "/search", params={"q": "' OR '1'='1"}, headers=auth()
    )
    assert r.status_code == 200
    assert r.json()["items"] == []
