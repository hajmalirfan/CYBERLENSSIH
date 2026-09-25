"""SecuriX Temporal Orchestrator API Service.

Exposes REST endpoints to trigger multi-tool scan workflows and check execution status.
Called by Backstage/SecuriX portal 'Run Investigation' button or CI/CD webhooks.
"""
import logging
import os
import sys
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure service directory is in sys.path
sys.path.insert(0, os.path.dirname(__file__))
from workflows import run_security_scan_workflow, determine_applicable_tools

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("temporal-orchestrator")

app = FastAPI(
    title="SecuriX Temporal Orchestrator",
    description="Workflow orchestrator that decides which scanner tools to invoke and aggregates results.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

WORKFLOW_RESULTS: Dict[str, Dict[str, Any]] = {}


class ScanWorkflowRequest(BaseModel):
    target: str
    tools: Optional[List[str]] = None
    target_type: Optional[str] = None  # repo, container, web, host, all


@app.get("/health")
def health():
    return {"status": "ok", "service": "temporal-orchestrator"}


@app.post("/api/orchestrator/scan")
async def trigger_scan(req: ScanWorkflowRequest):
    """Trigger a multi-tool security investigation workflow."""
    result = await run_security_scan_workflow(
        target=req.target,
        tools=req.tools,
        target_type=req.target_type
    )
    wf_id = result["workflow_id"]
    WORKFLOW_RESULTS[wf_id] = result
    return result


@app.get("/api/orchestrator/status/{workflow_id}")
def get_workflow_status(workflow_id: str):
    """Check workflow progress and inspect aggregated findings."""
    result = WORKFLOW_RESULTS.get(workflow_id)
    if not result:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return result


@app.post("/api/orchestrator/investigate/{finding_id}")
async def investigate_finding(finding_id: str):
    """Trigger InvestigateAssetWorkflow for a serious finding (Section 6.1)."""
    from workflows import InvestigateAssetWorkflow
    wf = InvestigateAssetWorkflow()
    result = await wf.run(finding_id)
    return result


@app.post("/api/orchestrator/reverify/{finding_id}")
async def reverify_finding(finding_id: str, new_sha: str = "HEAD"):
    """Trigger ReverifyFindingWorkflow after a code fix (Section 6.4)."""
    from workflows import ReverifyFindingWorkflow
    wf = ReverifyFindingWorkflow()
    result = await wf.run(finding_id, new_sha)
    return result


@app.post("/api/orchestrator/onboard/{repo_id}")
async def onboard_repo(repo_id: str):
    """Trigger OnboardingWorkflow for repository (Section 11.3)."""
    from workflows import OnboardingWorkflow
    wf = OnboardingWorkflow()
    result = await wf.run(repo_id)
    return result


@app.get("/api/orchestrator/tools")
def list_supported_tools():
    """List all supported scanner tools and target mappings."""
    return {
        "supported_tools": ["semgrep", "checkov", "cosign", "falco", "suricata", "zap", "gitleaks", "trivy"],
        "target_mappings": {
            "repo": ["semgrep", "checkov", "gitleaks", "trivy"],
            "container": ["cosign", "falco"],
            "web": ["zap", "suricata"],
            "all": ["semgrep", "checkov", "cosign", "falco", "suricata", "zap"],
        }
    }

