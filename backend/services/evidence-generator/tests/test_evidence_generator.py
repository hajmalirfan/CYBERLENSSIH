"""Unit tests for SecuriX Evidence Pack Generator."""
import importlib.util
import os
import pytest
from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "evidence_generator_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


app = _load_app()
client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "evidence-generator"


def test_generate_pack():
    payload = {
        "asset_id": "repo://fintech/payment-gateway",
        "format": "html"
    }
    response = client.post("/api/evidence/generate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "pack_id" in data
    assert "sha256" in data
    assert len(data["sha256"]) == 64  # Valid SHA-256 length
    assert "download_url" in data

    # Verify download of HTML report
    pack_id = data["pack_id"]
    dl_html = client.get(f"/api/evidence/download/{pack_id}?format=html")
    assert dl_html.status_code == 200
    assert "SecuriX Verified Audit Evidence Pack" in dl_html.text
    assert "OpenTimestamps" in dl_html.text

    # Verify download of JSON report
    dl_json = client.get(f"/api/evidence/download/{pack_id}?format=json")
    assert dl_json.status_code == 200
    json_data = dl_json.json()
    assert json_data["pack_id"] == pack_id
    assert "cryptographic_proof" in json_data
