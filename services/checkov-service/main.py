"""SecuriX Checkov Security Service - IaC scanning."""
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

try:
    from shared.schemas.finding import Finding
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.schemas.finding import Finding

app = FastAPI(title="SecuriX Checkov Security Service")

RESULTS: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target: str
    framework: Optional[str] = None


def _publish_to_kafka(findings: List[Dict[str, Any]]) -> None:
    bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "")
    if not bootstrap:
        return
    try:
        from kafka import KafkaProducer

        producer = KafkaProducer(
            bootstrap_servers=bootstrap.split(","),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            request_timeout_ms=5000,
        )
        for f in findings:
            producer.send(os.getenv("KAFKA_TOPIC", "findings.raw"), value=f)
        producer.flush(timeout=5)
        producer.close(timeout=5)
    except Exception:
        return


def _extract_failed_checks(data: Any) -> List[Dict[str, Any]]:
    """Handle the shapes Checkov -o json can emit."""
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, dict):
            return results.get("failed_checks", []) or []
        if isinstance(results, list):
            out: List[Dict[str, Any]] = []
            for entry in results:
                if isinstance(entry, dict):
                    out.extend(entry.get("failed_checks", []) or [])
            return out
    if isinstance(data, list):
        out = []
        for entry in data:
            if isinstance(entry, dict):
                if "check_id" in entry:
                    out.append(entry)
                else:
                    res = entry.get("results", {})
                    if isinstance(res, dict):
                        out.extend(res.get("failed_checks", []) or [])
        return out
    return []


def normalize_checkov_check(scan_id: str, target: str, check: Dict[str, Any]) -> Dict[str, Any]:
    line_range = check.get("file_line_range") or [None]
    severity = (check.get("severity") or check.get("check_result", {}).get("severity") or "info")
    if isinstance(severity, dict):
        severity = severity.get("level", "info")
    finding = Finding(
        scan_id=scan_id,
        tool="checkov",
        target=target,
        rule_id=check.get("check_id") or check.get("bc_check_id"),
        title=check.get("check_name", check.get("check_id", "Checkov finding")),
        description=(check.get("check_result", {}) or {}).get("result")
        if isinstance(check.get("check_result"), dict)
        else None,
        severity=str(severity).lower(),
        file=check.get("repo_file_path") or check.get("file_path"),
        line=line_range[0] if line_range else None,
        column=None,
        category="iac",
        evidence=json.dumps({k: check.get(k) for k in ("resource", "check_class", "file_path") if k in check}),
        remediation=check.get("guideline"),
    )
    return finding.model_dump(mode="json")


@app.get("/health")
def health():
    return {"status": "ok", "tool": "checkov"}


@app.post("/scan")
def scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    command = ["checkov", "-d", request.target, "-o", "json"]
    if request.framework:
        command += ["--framework", request.framework]
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Checkov scan timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Checkov binary not found")

    if not process.stdout:
        raise HTTPException(status_code=500, detail=process.stderr or "Checkov returned no output")
    try:
        data = json.loads(process.stdout)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid Checkov JSON output")

    failed = _extract_failed_checks(data)
    findings = [normalize_checkov_check(scan_id, request.target, c) for c in failed]
    response = {
        "scan_id": scan_id,
        "tool": "checkov",
        "target": request.target,
        "findings": findings,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    RESULTS[scan_id] = response
    _publish_to_kafka(findings)
    return response


@app.get("/results/{scan_id}")
def get_result(scan_id: str):
    result = RESULTS.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result
