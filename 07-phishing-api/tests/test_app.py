from unittest.mock import patch, MagicMock

import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "status" in data
    assert data["status"] == "ok"


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
