"""Checkov service tests. Run from repo root with --import-mode=importlib, or per-service."""
import importlib.util
import json
import os
import subprocess

from fastapi.testclient import TestClient

SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_app():
    spec = importlib.util.spec_from_file_location(
        "checkov_service_main", os.path.join(SERVICE_DIR, "main.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


client = TestClient(_load_app())


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "tool": "checkov"}


def _fake_checkov_output():
    return {
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
                    "file_path": "/main.tf",
                    "repo_file_path": "main.tf",
                    "file_line_range": [1, 10],
                    "resource": "aws_s3_bucket.data",
                    "guideline": "https://example.com/guideline",
                    "severity": "HIGH",
                }
            ],
        }
    }


def test_scan(monkeypatch):
    class FakeProcess:
        stdout = json.dumps(_fake_checkov_output())
        stderr = ""
        returncode = 1

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcess())
    r = client.post("/scan", json={"target": "/workspace/terraform"})
    assert r.status_code == 200
    data = r.json()
    assert data["tool"] == "checkov"
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["rule_id"] == "CKV_AWS_20"
    assert f["category"] == "iac"
    assert f["severity"] == "high"
    assert f["file"] == "main.tf"


def test_results_roundtrip(monkeypatch):
    class FakeProcess:
        stdout = json.dumps({"results": {"failed_checks": []}})
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcess())
    scan_id = client.post("/scan", json={"target": "/workspace/terraform"}).json()["scan_id"]
    assert client.get(f"/results/{scan_id}").status_code == 200
    assert client.get("/results/nope").status_code == 404
