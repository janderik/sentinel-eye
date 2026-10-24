import pytest
from fastapi.testclient import TestClient

from src.api import routes
from src.storage import database


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setattr(database, "_db_manager", None)
    monkeypatch.setattr(routes, "_rule_engine", None)

    from src.api.server import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


RULE = {
    "rule_id": "custom-ssh-bruteforce",
    "name": "SSH brute force",
    "severity": "high",
    "source": "syslog/*",
    "event_type": "syslog",
    "conditions": [{"field": "data.message", "operator": "contains", "value": "Failed password"}],
}


def test_create_rule(client):
    response = client.post("/api/v1/rules", json=RULE)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "created"
    assert body["rule"]["severity"] == "high"

    rules = client.get("/api/v1/rules").json()["rules"]
    assert any(r["rule_id"] == "custom-ssh-bruteforce" for r in rules)


def test_create_rule_rejects_invalid_severity(client):
    response = client.post("/api/v1/rules", json={**RULE, "severity": "catastrophic"})
    assert response.status_code == 400


def test_create_rule_requires_fields(client):
    response = client.post("/api/v1/rules", json={"name": "incomplete"})
    assert response.status_code == 400
