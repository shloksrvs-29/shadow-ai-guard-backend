import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
HEADERS = {"X-API-Key": "dev-local-key-change-me"}


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_analyze_requires_api_key():
    r = client.post("/api/v1/analyze", json={"text": "hello"})
    assert r.status_code == 422 or r.status_code == 401  # missing header


def test_analyze_rejects_bad_api_key():
    r = client.post("/api/v1/analyze", json={"text": "hello"}, headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


def test_analyze_blocks_secret():
    r = client.post(
        "/api/v1/analyze",
        json={"text": "key: AKIAIOSFODNN7EXAMPLE", "platform": "chatgpt", "user_id": "u1", "org_id": "acme"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "block"


def test_analyze_allows_safe_text():
    r = client.post(
        "/api/v1/analyze",
        json={"text": "Write a short poem about rivers.", "platform": "chatgpt"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"


def test_login_and_audit_flow():
    login = client.post("/api/v1/auth/token", data={"username": "admin", "password": "changeme"})
    assert login.status_code == 200
    token = login.json()["access_token"]

    audit = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
    assert audit.status_code == 200

    verify = client.get("/api/v1/audit/verify", headers={"Authorization": f"Bearer {token}"})
    assert verify.status_code == 200
    assert verify.json()["valid"] is True
