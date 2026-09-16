"""Cosign service tests. Run from repo root with --import-mode=importlib, or per-service."""
import importlib.util
import os
import subprocess

from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "cosign_service_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


client = TestClient(_load_app())


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "tool": "cosign"}


def test_scan_verified(monkeypatch):
    class FakeProcess:
        stdout = "Verified OK"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcess())
    r = client.post("/scan", json={"target": "ghcr.io/example/app:latest"})
    assert r.status_code == 200
    data = r.json()
    assert data["tool"] == "cosign"
    assert data["findings"][0]["severity"] == "info"
    assert data["findings"][0]["category"] == "supply-chain"
    assert "passed" in data["findings"][0]["title"]


def test_scan_failed(monkeypatch):
    class FakeProcess:
        stdout = ""
        stderr = "no matching signatures"
        returncode = 1

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcess())
    r = client.post("/scan", json={"target": "ghcr.io/example/app:latest"})
    assert r.status_code == 200
    assert r.json()["findings"][0]["severity"] == "high"


def test_results_roundtrip(monkeypatch):
    class FakeProcess:
        stdout = "ok"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcess())
    scan_id = client.post("/scan", json={"target": "img:tag"}).json()["scan_id"]
    assert client.get(f"/results/{scan_id}").status_code == 200
    assert client.get("/results/nope").status_code == 404
