"""SecuriX Falco Service - runtime threat detection events.

Target semantics (explicit, since Falco is NOT a static scanner):
  - "runtime"            -> capture live Falco events for a short window
  - path to JSON-lines file -> parse each line as a Falco event
  - any other string     -> passed to Falco CLI, stdout parsed as JSON lines
"""
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

try:
    from shared.schemas.finding import Finding
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.schemas.finding import Finding

app = FastAPI(title="SecuriX Falco Security Service")

RESULTS: Dict[str, Dict[str, Any]] = {}

PRIORITY_TO_SEVERITY = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
    "informational": "info",
    "debug": "info",
}


class ScanRequest(BaseModel):
    target: str


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


def normalize_falco_event(scan_id: str, target: str, event: Dict[str, Any]) -> Dict[str, Any]:
    priority = str(event.get("priority", "Notice")).lower()
    finding = Finding(
        scan_id=scan_id,
        tool="falco",
        target=target,
        rule_id=event.get("rule"),
        title=event.get("rule", "Falco runtime event"),
        description=event.get("output"),
        severity=PRIORITY_TO_SEVERITY.get(priority, "info"),
        file=None,
        line=None,
        column=None,
        category="runtime",
        evidence=json.dumps(event.get("output_fields", event))[:4000],
        remediation=None,
    )
    return finding.model_dump(mode="json")


def parse_json_lines(text: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
        except json.JSONDecodeError:
            continue
    return events


@app.get("/health")
def health():
    return {"status": "ok", "tool": "falco"}


@app.post("/scan")
def scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    events: List[Dict[str, Any]] = []

    # File input: parse directly without requiring the Falco daemon.
    if os.path.isfile(request.target):
        try:
            with open(request.target, "r", encoding="utf-8") as fh:
                events = parse_json_lines(fh.read())
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"Cannot read Falco event file: {exc}")
    else:
        command = ["falco", "-o", "json_output=true", "-o", "log_stderr=false"]
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="Falco capture timed out")
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="Falco binary not found")
        events = parse_json_lines(process.stdout or "")

    findings = [normalize_falco_event(scan_id, request.target, e) for e in events]
    response = {
        "scan_id": scan_id,
        "tool": "falco",
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
