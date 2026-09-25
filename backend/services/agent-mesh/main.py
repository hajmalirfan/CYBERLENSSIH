"""SecuriX Agent Mesh Service.

Combines AI reasoning, PyFair Monte Carlo risk quantification (in ₹),
OPA regulatory compliance evaluation (RBI, SEBI, ISO 27001, NIST, DPDP),
and business-contextual vulnerability prioritization.
"""
import logging
import os
import sys
from typing import Any, Dict, List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(__file__))
from pyfair_engine import FAIRSimulationEngine
from opa_engine import OPAComplianceEngine
from prioritizer import PrioritizationAgent

# LLM Gateway client
try:
    from shared.llm.client import SecuriXLLMClient
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.llm.client import SecuriXLLMClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent-mesh")

app = FastAPI(
    title="SecuriX AI Agent Mesh",
    description="Quantification Agent (PyFair ₹), Compliance Agent (OPA), and Prioritization Agent.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

fair_engine = FAIRSimulationEngine()
opa_engine = OPAComplianceEngine()
prioritizer = PrioritizationAgent()
llm_client = SecuriXLLMClient()


class QuantifyRequest(BaseModel):
    severity: str = "high"
    criticality: Optional[str] = "HIGH"
    iterations: Optional[int] = 1000


class FindingAnalysisRequest(BaseModel):
    finding: Dict[str, Any]
    asset_criticality: Optional[str] = "HIGH"


class BatchAnalysisRequest(BaseModel):
    findings: List[Dict[str, Any]]


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "agent-mesh",
        "agents": ["Quantification (FAIR ₹)", "Compliance (OPA)", "Prioritization"]
    }


@app.get("/api/agent/config")
def get_agent_config():
    """Returns agent mesh LLM gateway endpoints, available models, and API key status."""
    return {
        "agent_service_port": 8013,
        "litellm_gateway_url": os.getenv("LITELLM_GATEWAY_URL", "http://litellm:4000/v1"),
        "gateway_chat_endpoint": f"{os.getenv('LITELLM_GATEWAY_URL', 'http://localhost:4000/v1')}/chat/completions",
        "models_supported": ["gpt-4o-mini", "claude-3-5-sonnet", "gemini-1.5-pro", "ollama-mistral"],
        "api_keys_configured": {
            "openai": bool(os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_API_KEY") != "sk-mock"),
            "anthropic": bool(os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_API_KEY") != "sk-mock"),
            "gemini": bool(os.getenv("GEMINI_API_KEY") and os.getenv("GEMINI_API_KEY") != "sk-mock"),
        },
        "env_file_location": ".env at repository root"
    }


@app.post("/api/agent/quantify")
def quantify_loss(req: QuantifyRequest):
    """Run PyFair Monte Carlo simulation to calculate risk exposure in Indian Rupees (₹)."""
    return fair_engine.simulate(
        severity=req.severity,
        criticality=req.criticality or "HIGH",
        iterations=req.iterations or 1000,
    )


@app.post("/api/agent/compliance")
def evaluate_compliance(req: FindingAnalysisRequest):
    """Evaluate finding against RBI, SEBI, ISO 27001, NIST CSF, and DPDP Act."""
    verdicts = opa_engine.evaluate(req.finding)
    return {"verdicts": verdicts}


@app.post("/api/agent/prioritize")
def prioritize_finding(req: FindingAnalysisRequest):
    """Compute financial composite priority tier for finding."""
    finding_data = dict(req.finding)
    finding_data["criticality"] = req.asset_criticality
    return prioritizer.prioritize_finding(finding_data)


@app.post("/api/agent/pipeline")
async def run_full_pipeline(req: FindingAnalysisRequest):
    """Execute complete analysis pipeline: Quantify ₹ -> OPA Compliance -> Prioritize."""
    finding = dict(req.finding)
    sev = finding.get("severity", "medium")
    crit = req.asset_criticality or "HIGH"

    # 1. Run FAIR simulation
    fair_results = fair_engine.simulate(severity=sev, criticality=crit)
    finding["fair_exposure"] = fair_results

    # 2. Evaluate OPA compliance
    verdicts = opa_engine.evaluate(finding)
    finding["opa_verdicts"] = verdicts

    # 3. Compute business priority
    finding["criticality"] = crit
    priority = prioritizer.prioritize_finding(finding)

    # 4. LiteLLM Gateway Heuristic Reasoning
    llm_summary = await llm_client.chat_completion(
        messages=[
            {"role": "system", "content": "You are the SecuriX Cyber Risk AI Agent."},
            {"role": "user", "content": f"Summarize business risk for finding: {finding.get('title')} with {fair_results['formatted_inr']} exposure."}
        ]
    )

    return {
        "finding_title": finding.get("title"),
        "fair_exposure": fair_results,
        "opa_verdicts": verdicts,
        "priority": priority,
        "ai_rationale": llm_summary.get("content"),
    }
