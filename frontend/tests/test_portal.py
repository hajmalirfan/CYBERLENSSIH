"""Unit tests for SecuriX Portal Server."""
import importlib.util
import os
import pytest
from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "portal_server_main", os.path.join(SERVICE_DIR, "server.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


app = _load_app()
client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "portal"


def test_serve_index():
    response = client.get("/")
    assert response.status_code == 200
    assert "CYBERLENS" in response.text


def test_proxy_risk_queue():
    response = client.get("/graph/risk-queue")
    assert response.status_code == 200
    items = response.json()
    assert len(items) > 0
    assert "expected_annual_loss_inr" in items[0]


def test_proxy_compliance():
    response = client.get("/graph/compliance")
    assert response.status_code == 200
    assert "frameworks" in response.json()
