"""SecuriX Cosign Service - container image / artifact signature verification."""
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

app = FastAPI(title="SecuriX Cosign Security Service")

RESULTS: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target: str
    key_ref: Optional[str] = None


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


def build_finding(scan_id: str, target: str, verified: bool, evidence: str) -> Dict[str, Any]:
    finding = Finding(
        scan_id=scan_id,
        tool="cosign",
        target=target,
        rule_id="cosign.signature-verification",
        title="Image signature verification " + ("passed" if verified else "failed"),
        description="Cosign reports the image signature is valid."
        if verified
        else "Cosign could not verify a valid signature for this image.",
        severity="info" if verified else "high",
        file=None,
        line=None,
        column=None,
        category="supply-chain",
        evidence=evidence,
        remediation=None if verified else "Sign the image with `cosign sign` and verify with the correct key.",
    )
    return finding.model_dump(mode="json")


@app.get("/health")
def health():
    return {"status": "ok", "tool": "cosign"}


@app.post("/scan")
def scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    command = ["cosign", "verify", request.target]
    if request.key_ref:
        command += ["--key", request.key_ref]
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Cosign verification timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Cosign binary not found")

    verified = process.returncode == 0
    evidence = (process.stdout or "") + (process.stderr or "")
    findings = [build_finding(scan_id, request.target, verified, evidence.strip()[:4000])]
    response = {
        "scan_id": scan_id,
        "tool": "cosign",
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
