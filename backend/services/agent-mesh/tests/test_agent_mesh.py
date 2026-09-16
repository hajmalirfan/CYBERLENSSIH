"""Unit tests for SecuriX Agent Mesh."""
import importlib.util
import os
import pytest
from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "agent_mesh_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


app = _load_app()
client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "agent-mesh"


def test_quantify_inr():
    payload = {"severity": "critical", "criticality": "CRITICAL", "iterations": 500}
    response = client.post("/api/agent/quantify", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "expected_annual_loss_inr" in data
    assert data["expected_annual_loss_inr"] > 0
    assert "formatted_inr" in data
    assert "₹" in data["formatted_inr"]
    assert "exceedance_curve" in data
    assert len(data["exceedance_curve"]) > 0


def test_compliance_evaluation():
    sample_finding = {
        "title": "Hardcoded JWT Token in Payment Service",
        "description": "Found JWT private secret key in source code",
        "rule_id": "generic.secrets.jwt",
        "tool": "semgrep",
    }
    response = client.post("/api/agent/compliance", json={"finding": sample_finding})
    assert response.status_code == 200
    data = response.json()
    assert "verdicts" in data
    regs = [v["regulation"] for v in data["verdicts"]]
    assert "RBI" in regs
    assert "ISO27001" in regs
    assert "DPDP" in regs


def test_prioritization():
    sample_finding = {
        "title": "Public S3 Bucket",
        "severity": "high",
        "fair_exposure": {"expected_annual_loss_inr": 2500000.0}
    }
    response = client.post(
        "/api/agent/prioritize",
        json={"finding": sample_finding, "asset_criticality": "CRITICAL"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "composite_score" in data
    assert "priority_tier" in data
    assert "recommended_action" in data


def test_full_pipeline():
    sample_finding = {
        "title": "SQL Injection on Transfer API",
        "severity": "critical",
        "tool": "zap",
    }
    response = client.post(
        "/api/agent/pipeline",
        json={"finding": sample_finding, "asset_criticality": "CRITICAL"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "fair_exposure" in data
    assert "opa_verdicts" in data
    assert "priority" in data
    assert "ai_rationale" in data
