"""SecuriX OWASP ZAP Service - web application scanning.

Target semantics: `target` is a base URL, e.g. http://example-app:8080
Runs `zap-baseline.py -t <target> -J <report> -I` then normalizes alerts.
"""
import json
import os
import subprocess
import sys
import tempfile
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

app = FastAPI(title="SecuriX ZAP Security Service")

RESULTS: Dict[str, Dict[str, Any]] = {}


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


def _risk_to_severity(risk: str) -> str:
    # ZAP riskdesc looks like "Medium (High)": first token is risk, parens are confidence.
    first = (risk or "").strip().split()[0].lower() if (risk or "").strip() else ""
    if first.startswith("high"):
        return "high"
    if first.startswith("medium"):
        return "medium"
    if first.startswith("low"):
        return "low"
    return "info"


def normalize_zap_alert(scan_id: str, target: str, alert: Dict[str, Any]) -> Dict[str, Any]:
    instances = alert.get("instances") or []
    evidence = None
    if instances:
        first = instances[0]
        evidence = first.get("uri") or first.get("evidence") or json.dumps(first)[:2000]
    finding = Finding(
        scan_id=scan_id,
        tool="zap",
        target=target,
        rule_id=str(alert.get("pluginid") or alert.get("alertRef", "")) or None,
        title=alert.get("name", "ZAP finding"),
        description=alert.get("desc"),
        severity=_risk_to_severity(alert.get("riskdesc", "") or alert.get("riskcode", "")),
        file=None,
        line=None,
        column=None,
        category="web",
        evidence=evidence,
        remediation=alert.get("solution"),
    )
    return finding.model_dump(mode="json")


def extract_alerts(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    for key in ("site", "sites"):
        for site in report.get(key, []) or []:
            if isinstance(site, dict):
                alerts.extend(site.get("alerts", []) or [])
    return alerts


@app.get("/health")
def health():
    return {"status": "ok", "tool": "zap"}


@app.post("/scan")
def scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name
    command = ["zap-baseline.py", "-t", request.target, "-J", report_path, "-I"]
    try:
        try:
            subprocess.run(command, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="ZAP binary not found")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="ZAP scan timed out")
        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                report = json.load(fh)
        except (OSError, json.JSONDecodeError):
            raise HTTPException(status_code=500, detail="Invalid ZAP JSON report")
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass

    findings = [normalize_zap_alert(scan_id, request.target, a) for a in extract_alerts(report)]
    response = {
        "scan_id": scan_id,
        "tool": "zap",
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
