"""SecuriX Suricata Service - network IDS alerts from pcap / eve.json.

Target semantics:
  - path to .pcap           -> run `suricata -r <pcap>` then parse eve.json
  - path to eve.json        -> parse alerts directly
  - path to directory       -> look for eve.json inside
"""
import glob
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

app = FastAPI(title="SecuriX Suricata Security Service")

RESULTS: Dict[str, Dict[str, Any]] = {}

SURICATA_SEVERITY_MAP = {"1": "high", "2": "medium", "3": "low"}


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


def normalize_suricata_alert(scan_id: str, target: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    alert = entry.get("alert") or {}
    sev_raw = str(alert.get("severity", ""))
    finding = Finding(
        scan_id=scan_id,
        tool="suricata",
        target=target,
        rule_id=str(alert.get("signature_id", "")) or None,
        title=alert.get("signature", "Suricata alert"),
        description=alert.get("category"),
        severity=SURICATA_SEVERITY_MAP.get(sev_raw, "info"),
        file=target,
        line=None,
        column=None,
        category="network",
        evidence=json.dumps(
            {k: entry.get(k) for k in ("src_ip", "dest_ip", "proto", "alert") if k in entry}
        ),
        remediation=None,
    )
    return finding.model_dump(mode="json")


def load_eve_entries(path: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    candidates: List[str] = []
    if os.path.isdir(path):
        candidates = glob.glob(os.path.join(path, "eve.json"))
    elif os.path.isfile(path):
        if os.path.basename(path) == "eve.json":
            candidates = [path]
        else:
            # A pcap was given but eve.json not produced yet -> caller runs suricata first.
            candidates = []
    for cand in candidates:
        with open(cand, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("event_type") == "alert":
                    entries.append(obj)
    return entries


@app.get("/health")
def health():
    return {"status": "ok", "tool": "suricata"}


@app.post("/scan")
def scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    target = request.target
    entries: List[Dict[str, Any]] = []

    if os.path.isfile(target) and os.path.basename(target) != "eve.json":
        # Assume pcap: invoke suricata, output to temp log dir.
        log_dir = os.getenv("SURICATA_LOG_DIR", "/tmp/suricata")
        os.makedirs(log_dir, exist_ok=True)
        command = ["suricata", "-c", os.getenv("SURICATA_CONFIG", "/etc/suricata/suricata.yaml"),
                   "-r", target, "-l", log_dir]
        try:
            subprocess.run(command, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="Suricata scan timed out")
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="Suricata binary not found")
        entries = load_eve_entries(log_dir)
    else:
        entries = load_eve_entries(target)

    findings = [normalize_suricata_alert(scan_id, target, e) for e in entries]
    response = {
        "scan_id": scan_id,
        "tool": "suricata",
        "target": target,
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
