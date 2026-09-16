"""Falco service tests. Run from repo root with --import-mode=importlib, or per-service."""
import importlib.util
import json
import os
import subprocess

from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "falco_service_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


client = TestClient(_load_app())


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "tool": "falco"}


def test_scan_from_subprocess(monkeypatch):
    event = {
        "output": "Sensitive file opened for reading",
        "priority": "Warning",
        "rule": "Read sensitive file untrusted",
        "time": "2026-09-16T00:00:00Z",
        "output_fields": {"fd.name": "/etc/shadow"},
    }

    class FakeProcess:
        stdout = json.dumps(event) + "\n"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcess())
    r = client.post("/scan", json={"target": "runtime"})
    assert r.status_code == 200
    data = r.json()
    assert data["tool"] == "falco"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "Read sensitive file untrusted"
    assert data["findings"][0]["severity"] == "medium"
    assert data["findings"][0]["category"] == "runtime"


def test_scan_from_file(tmp_path):
    event = {"output": "x", "priority": "Critical", "rule": "R", "output_fields": {}}
    p = tmp_path / "events.json"
    p.write_text(json.dumps(event) + "\n")
    r = client.post("/scan", json={"target": str(p)})
    assert r.status_code == 200
    assert r.json()["findings"][0]["severity"] == "critical"


def test_results_roundtrip(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("")
    scan_id = client.post("/scan", json={"target": str(p)}).json()["scan_id"]
    assert client.get(f"/results/{scan_id}").status_code == 200
    assert client.get("/results/nope").status_code == 404
