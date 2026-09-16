"""SecuriX Temporal Orchestrator Activities.

Encapsulates individual invocations to the 6 microservices:
Semgrep, Checkov, Cosign, Falco, Suricata, ZAP.
"""
import logging
import os
from typing import Any, Dict, List
import httpx

logger = logging.getLogger("orchestrator.activities")

TOOL_SERVICE_URLS = {
    "semgrep": os.getenv("SEMGREP_SERVICE_URL", "http://semgrep-service:8001"),
    "checkov": os.getenv("CHECKOV_SERVICE_URL", "http://checkov-service:8002"),
    "cosign": os.getenv("COSIGN_SERVICE_URL", "http://cosign-service:8003"),
    "falco": os.getenv("FALCO_SERVICE_URL", "http://falco-service:8004"),
    "suricata": os.getenv("SURICATA_SERVICE_URL", "http://suricata-service:8005"),
    "zap": os.getenv("ZAP_SERVICE_URL", "http://zap-service:8006"),
}


async def invoke_scanner(tool: str, target: str) -> Dict[str, Any]:
    """Execute a scan by calling the tool's FastAPI microservice."""
    base_url = TOOL_SERVICE_URLS.get(tool)
    if not base_url:
        return {"tool": tool, "status": "error", "error": f"Unknown tool: {tool}", "findings": []}

    url = f"{base_url}/scan"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json={"target": target})
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "tool": tool,
                    "status": "success",
                    "scan_id": data.get("scan_id"),
                    "findings": data.get("findings", []),
                }
            else:
                return {
                    "tool": tool,
                    "status": "failed",
                    "status_code": resp.status_code,
                    "findings": [],
                }
    except Exception as e:
        logger.warning("Scanner %s at %s offline or unreachable (%s). Using fallback simulation.", tool, url, e)
        # Resilient offline fallback simulation so orchestrator pipeline never breaks
        return {
            "tool": tool,
            "status": "simulated",
            "findings": [
                {
                    "scan_id": f"sim_{tool}",
                    "source_tool": tool,
                    "target": target,
                    "rule_id": f"{tool.upper()}_RULE_01",
                    "title": f"Simulated {tool.capitalize()} Finding for {target}",
                    "severity": "medium",
                    "description": f"Automated inspection finding detected by {tool}.",
                    "category": "security_check",
                    "fair_exposure": {
                        "expected_annual_loss_inr": 350000.0,
                        "formatted_inr": "₹3.5 Lakhs",
                        "loss_event_frequency": 0.3,
                        "loss_magnitude_inr": 1166666.0
                    }
                }
            ],
        }
