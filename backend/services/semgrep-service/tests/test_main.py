"""Semgrep service tests. Run from repo root with --import-mode=importlib, or per-service."""
import importlib.util
import json
import os
import subprocess

from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "semgrep_service_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


client = TestClient(_load_app())


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["tool"] == "semgrep"


def test_scan(monkeypatch):
    fake_output = {
        "results": [
            {
                "check_id": "test.rule",
                "path": "app.py",
                "start": {"line": 10, "col": 5},
                "extra": {
                    "message": "Test finding",
                    "severity": "WARNING",
                    "lines": "dangerous code",
                    "metadata": {"description": "desc"},
                },
            }
        ]
    }

    class FakeProcess:
        stdout = json.dumps(fake_output)
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcess())

    response = client.post("/scan", json={"target": "/workspace/demo"})
    assert response.status_code == 200
    data = response.json()
    assert data["tool"] == "semgrep"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "test.rule"
    assert data["findings"][0]["severity"] == "warning"
    assert data["findings"][0]["file"] == "app.py"
    assert data["findings"][0]["line"] == 10
    assert data["findings"][0]["column"] == 5


def test_results_roundtrip(monkeypatch):
    class FakeProcess:
        stdout = json.dumps({"results": []})
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcess())
    scan = client.post("/scan", json={"target": "/workspace/demo"}).json()
    scan_id = scan["scan_id"]

    ok = client.get(f"/results/{scan_id}")
    assert ok.status_code == 200
    assert ok.json()["scan_id"] == scan_id

    missing = client.get("/results/does-not-exist")
    assert missing.status_code == 404
