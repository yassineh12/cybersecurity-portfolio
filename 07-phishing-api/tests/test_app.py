from unittest.mock import patch, MagicMock

import pytest

import app as app_module
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app_module._rate_limits.clear()
    app_module._metrics["total_requests"] = 0
    app_module._metrics["total_response_time_ms"] = 0.0
    with app.test_client() as c:
        yield c


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "version" in data


def test_predict_without_model(client):
    resp = client.post("/predict", json={"url": "https://example.com"})
    assert resp.status_code == 503


def test_predict_missing_url(client):
    resp = client.post("/predict", json={})
    assert resp.status_code == 400


def test_predict_no_json(client):
    resp = client.post("/predict", data="not json")
    assert resp.status_code == 400


def test_batch_without_model(client):
    resp = client.post("/batch", json={"urls": ["https://example.com"]})
    assert resp.status_code == 503


def test_batch_missing_urls(client):
    resp = client.post("/batch", json={})
    assert resp.status_code == 400


def test_request_id_header(client):
    resp = client.get("/health")
    assert "X-Request-ID" in resp.headers
    assert len(resp.headers["X-Request-ID"]) == 32


def test_cors_headers(client):
    resp = client.get("/health")
    assert resp.headers["Access-Control-Allow-Origin"] == "*"
    assert "POST" in resp.headers["Access-Control-Allow-Methods"]


def test_docs_endpoint(client):
    resp = client.get("/docs")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "openapi" in data
    assert "paths" in data
    assert "/predict" in data["paths"]
    assert "/batch" in data["paths"]
    assert "/health" in data["paths"]


def test_metrics_endpoint(client):
    client.get("/health")
    client.get("/health")
    resp = client.get("/metrics")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total_requests"] >= 2
    assert "average_response_time_ms" in data
    assert "version" in data


def test_rate_limiting(client):
    saved = app_module.RATE_LIMIT_MAX
    app_module.RATE_LIMIT_MAX = 3
    try:
        for _ in range(3):
            client.post("/predict", json={"url": "https://example.com"})
        resp = client.post("/predict", json={"url": "https://example.com"})
        assert resp.status_code == 429
    finally:
        app_module.RATE_LIMIT_MAX = saved


def test_batch_truncates_over_100(client):
    resp = client.post("/batch", json={"urls": ["https://example.com"] * 150})
    assert resp.status_code == 503
