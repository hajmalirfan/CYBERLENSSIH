"""SecuriX Semgrep Security Service (reference implementation)."""
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

try:
    from shared.schemas.finding import Finding
except ImportError:  # pragma: no cover - local/pytest fallback
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.schemas.finding import Finding

app = FastAPI(title="SecuriX Semgrep Security Service")

RESULTS: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target: str
    config: Optional[str] = "auto"


def _publish_to_kafka(tool: str, findings: List[Dict[str, Any]]) -> None:
    """Best-effort publish of normalized findings to Kafka topic findings.raw.

    Disabled unless KAFKA_BOOTSTRAP_SERVERS is set. Never raises.
    """
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


def normalize_semgrep_result(scan_id: str, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    start = result.get("start") or {}
    finding = Finding(
        scan_id=scan_id,
        tool="semgrep",
        target=target,
        rule_id=result.get("check_id"),
        title=extra.get("message", result.get("check_id", "Semgrep finding")),
        description=metadata.get("description"),
        severity=str(extra.get("severity", "info")).lower(),
        file=result.get("path"),
        line=start.get("line"),
        column=start.get("col"),
        category="code",
        evidence=extra.get("lines"),
        remediation=metadata.get("fix") or metadata.get("remediation"),
    )
    return finding.model_dump(mode="json")


@app.get("/health")
def health():
    return {"status": "ok", "tool": "semgrep"}


@app.post("/scan")
def scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    command = ["semgrep", "--config", request.config or "auto", "--json", request.target]
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Semgrep scan timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Semgrep binary not found")

    if not process.stdout:
        raise HTTPException(status_code=500, detail=process.stderr or "Semgrep returned no output")

    try:
        data = json.loads(process.stdout)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid Semgrep JSON output")

    findings = [normalize_semgrep_result(scan_id, request.target, r) for r in data.get("results", [])]

    response = {
        "scan_id": scan_id,
        "tool": "semgrep",
        "target": request.target,
        "findings": findings,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    RESULTS[scan_id] = response
    _publish_to_kafka("semgrep", findings)
    return response


@app.get("/results/{scan_id}")
def get_result(scan_id: str):
    result = RESULTS.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result
