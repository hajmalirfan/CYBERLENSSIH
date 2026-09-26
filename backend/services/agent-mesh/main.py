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

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env"))
    load_dotenv()
except ImportError:
    pass

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


class OllamaChatRequest(BaseModel):
    prompt: str
    finding: Optional[Dict[str, Any]] = None
    model: Optional[str] = None
    system_prompt: Optional[str] = None


class OllamaRemediationRequest(BaseModel):
    finding: Dict[str, Any]
    model: Optional[str] = None


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "agent-mesh",
        "agents": ["Quantification (FAIR ₹)", "Compliance (OPA)", "Prioritization", "Ollama AI Assistant"]
    }


@app.get("/api/agent/config")
async def get_agent_config():
    """Returns agent mesh LLM gateway and Ollama endpoints, models, and status."""
    ollama_stat = await llm_client.check_ollama_status()
    return {
        "agent_service_port": 8013,
        "ollama": {
            "base_url": llm_client.ollama_base_url,
            "configured_model": llm_client.ollama_model,
            "connected": ollama_stat.get("connected", False),
            "available_models": ollama_stat.get("available_models", []),
            "version": ollama_stat.get("version"),
            "latency_ms": ollama_stat.get("latency_ms"),
            "message": ollama_stat.get("message")
        },
        "litellm_gateway_url": os.getenv("LITELLM_GATEWAY_URL", "http://litellm:4000/v1"),
        "gateway_chat_endpoint": f"{os.getenv('LITELLM_GATEWAY_URL', 'http://localhost:4000/v1')}/chat/completions",
        "models_supported": ["ollama-mistral", "ollama-llama3", "gpt-4o-mini", "claude-3-5-sonnet", "gemini-1.5-pro"],
        "api_keys_configured": {
            "openai": bool(os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_API_KEY") != "sk-mock"),
            "anthropic": bool(os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_API_KEY") != "sk-mock"),
            "gemini": bool(os.getenv("GEMINI_API_KEY") and os.getenv("GEMINI_API_KEY") != "sk-mock"),
        },
        "env_file_location": ".env at repository root"
    }


@app.get("/api/agent/ollama/status")
async def get_ollama_status():
    """Live connectivity and installed model status of the connected Ollama instance."""
    return await llm_client.check_ollama_status()


@app.post("/api/agent/ollama/chat")
async def ollama_chat(req: OllamaChatRequest):
    """Direct conversation with Ollama regarding vulnerabilities, regulatory standards, or remediation."""
    system = req.system_prompt or (
        "You are SecuriX AI, an elite cybersecurity and risk quantification assistant for Indian enterprise environments. "
        "You provide actionable insights referencing RBI Master Directions, SEBI CSCRF, DPDP Act 2023, and FAIR ₹ calculations."
    )
    user_content = req.prompt
    if req.finding:
        user_content = (
            f"Finding Context:\n"
            f"- Title: {req.finding.get('title')}\n"
            f"- Tool: {req.finding.get('tool')}\n"
            f"- Rule: {req.finding.get('rule_id')}\n"
            f"- Asset: {req.finding.get('asset_id')}\n"
            f"- Severity: {req.finding.get('severity')}\n"
            f"- Loss Exposure (₹): {req.finding.get('formatted_exposure_inr') or req.finding.get('expected_annual_loss_inr')}\n\n"
            f"User Question: {req.prompt}"
        )

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content}
    ]

    result = await llm_client.chat_completion(messages, model=req.model)
    return result


@app.post("/api/agent/ollama/remediation")
async def ollama_generate_remediation(req: OllamaRemediationRequest):
    """Generate precise code fixes, Terraform patches, and step-by-step remediation plans with Ollama."""
    finding = req.finding
    prompt = (
        f"Generate a production-ready security patch and copy-paste remediation for the following finding:\n"
        f"Title: {finding.get('title')}\n"
        f"Tool: {finding.get('tool')}\n"
        f"Rule ID: {finding.get('rule_id')}\n"
        f"File Path: {finding.get('file_path')}\n"
        f"Line Number: {finding.get('line_number')}\n"
        f"Evidence: {finding.get('evidence')}\n\n"
        f"Format your response with:\n"
        f"1. Explanation of the root cause\n"
        f"2. Fixed code snippet (diff or replacement block)\n"
        f"3. Verification steps (how to test the fix)"
    )

    messages = [
        {"role": "system", "content": "You are a Senior Application Security Engineer specializing in remediating critical vulnerabilities."},
        {"role": "user", "content": prompt}
    ]
    return await llm_client.chat_completion(messages, model=req.model)


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
    """Execute complete analysis pipeline: Quantify ₹ -> OPA Compliance -> Prioritize -> Ollama Reasoning."""
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

    # 4. Ollama / AI Reasoning
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
        "ai_source": llm_summary.get("source"),
        "ai_model": llm_summary.get("model"),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8013"))
    uvicorn.run(app, host="0.0.0.0", port=port)

