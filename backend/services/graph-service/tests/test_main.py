"""Unit tests for SecuriX Graph Service."""
import importlib.util
import os
import pytest
from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "graph_service_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


app = _load_app()
client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "graph-service"


def test_risk_queue_sorted_by_inr():
    response = client.get("/graph/risk-queue")
    assert response.status_code == 200
    items = response.json()
    assert len(items) > 0

    # Verify sorting by expected_annual_loss_inr descending
    for i in range(len(items) - 1):
        assert items[i]["expected_annual_loss_inr"] >= items[i + 1]["expected_annual_loss_inr"]

    # Verify FAIR breakdown presence
    first = items[0]
    assert "fair_breakdown" in first
    assert "formatted_inr" in first["fair_breakdown"]
    assert "₹" in first["fair_breakdown"]["formatted_inr"]


def test_get_findings_filter():
    response = client.get("/graph/findings?tool=semgrep")
    assert response.status_code == 200
    items = response.json()
    for item in items:
        assert item["tool"] == "semgrep"


def test_get_asset_detail_and_trace():
    asset_id = "repo://fintech/payment-gateway"
    response = client.get(f"/graph/asset/{asset_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["asset"]["asset_id"] == asset_id
    assert "total_exposure_inr" in data
    assert "fair_aggregate" in data
    assert "compliance_verdicts" in data
    assert "blast_radius" in data


def test_compliance_summary():
    response = client.get("/graph/compliance")
    assert response.status_code == 200
    data = response.json()
    assert "frameworks" in data
    assert "RBI" in data["frameworks"]
    assert "SEBI" in data["frameworks"]
    assert "ISO27001" in data["frameworks"]
    assert "DPDP" in data["frameworks"]


def test_verify_toggle():
    fid = "semgrep_hardcoded_jwt_secret_001"
    response = client.post(f"/graph/findings/{fid}/verify", json={"analyst_name": "Test SecOps"})
    assert response.status_code == 200
    assert response.json()["success"] is True


def test_ingest_finding():
    finding_payload = {
        "scan_id": "test_scan_999",
        "source_tool": "semgrep",
        "target": "repo://test/sample-app",
        "rule_id": "python.lang.security.deserialization",
        "title": "Insecure Deserialization via Pickle",
        "severity": "critical",
        "description": "Untrusted data passed into pickle.loads()",
        "file_path": "app/worker.py",
        "line_number": 88,
        "category": "code",
        "fair_exposure": {
            "loss_event_frequency": 0.8,
            "loss_magnitude_inr": 8000000.0,
            "expected_annual_loss_inr": 6400000.0,
            "formatted_inr": "₹64.0 Lakhs",
        }
    }
    response = client.post("/graph/findings/ingest", json=finding_payload)
    assert response.status_code == 200
    assert response.json()["status"] == "ingested"
