"""ZAP service tests. Run from repo root with --import-mode=importlib, or per-service."""
import importlib.util
import json
import os
import subprocess

from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "zap_service_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


client = TestClient(_load_app())


def _zap_report():
    return {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "10021",
                        "alertRef": "10021",
                        "name": "X-Content-Type-Options Header Missing",
                        "riskdesc": "Medium (High)",
                        "desc": "The header was not set.",
                        "solution": "Set the header.",
                        "instances": [{"uri": "http://example-app:8080/"}],
                    }
                ]
            }
        ]
    }


def _fake_run(cmd, **kwargs):
    # cmd: [..., "-J", report_path, ...] -> write fake report
    report_path = cmd[cmd.index("-J") + 1]
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(_zap_report(), fh)

    class FakeProcess:
        stdout = ""
        stderr = ""
        returncode = 0

    return FakeProcess()


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "tool": "zap"}


def test_scan(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run)
    r = client.post("/scan", json={"target": "http://example-app:8080"})
    assert r.status_code == 200
    data = r.json()
    assert data["tool"] == "zap"
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["rule_id"] == "10021"
    assert f["category"] == "web"
    assert f["severity"] == "medium"


def test_results_roundtrip(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run)
    scan_id = client.post("/scan", json={"target": "http://example-app:8080"}).json()["scan_id"]
    assert client.get(f"/results/{scan_id}").status_code == 200
    assert client.get("/results/nope").status_code == 404
