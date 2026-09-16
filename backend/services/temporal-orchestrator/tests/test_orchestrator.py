"""Unit tests for SecuriX Temporal Orchestrator."""
import importlib.util
import os
import pytest
from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "temporal_orchestrator_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


app = _load_app()
client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "temporal-orchestrator"


def test_list_tools():
    response = client.get("/api/orchestrator/tools")
    assert response.status_code == 200
    data = response.json()
    assert "supported_tools" in data
    assert len(data["supported_tools"]) == 6


def test_trigger_scan_repo():
    payload = {
        "target": "repo://fintech/payment-service",
        "target_type": "repo"
    }
    response = client.post("/api/orchestrator/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "workflow_id" in data
    assert data["status"] == "COMPLETED"
    assert "semgrep" in data["tools_requested"]
    assert "checkov" in data["tools_requested"]
    assert data["total_findings"] >= 1

    # Verify status lookup by workflow_id
    wf_id = data["workflow_id"]
    status_resp = client.get(f"/api/orchestrator/status/{wf_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["workflow_id"] == wf_id
