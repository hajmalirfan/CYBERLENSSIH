"""Suricata service tests. Run from repo root with --import-mode=importlib, or per-service."""
import importlib.util
import json
import os

from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "suricata_service_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


client = TestClient(_load_app())


def _eve_alert():
    return {
        "timestamp": "2026-09-16T00:00:00Z",
        "event_type": "alert",
        "src_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
        "proto": "TCP",
        "alert": {
            "signature_id": 2100367,
            "signature": "ET SCAN Possible Nmap Scan",
            "category": "Attempted Information Leak",
            "severity": 2,
        },
    }


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "tool": "suricata"}


def test_scan_eve_file(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text(json.dumps(_eve_alert()) + "\n" + json.dumps({"event_type": "flow"}) + "\n")
    r = client.post("/scan", json={"target": str(p)})
    assert r.status_code == 200
    data = r.json()
    assert data["tool"] == "suricata"
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["rule_id"] == "2100367"
    assert f["severity"] == "medium"
    assert f["category"] == "network"


def test_results_roundtrip(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("")
    scan_id = client.post("/scan", json={"target": str(p)}).json()["scan_id"]
    assert client.get(f"/results/{scan_id}").status_code == 200
    assert client.get("/results/nope").status_code == 404
