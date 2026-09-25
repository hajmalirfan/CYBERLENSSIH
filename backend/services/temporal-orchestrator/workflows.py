"""SecuriX Temporal Orchestration Workflows.

Section 6.1, 6.4, and 11.3 of SecuriX Implementation Guide.
Coordinates InvestigateAssetWorkflow, ReverifyFindingWorkflow, and OnboardingWorkflow.
"""
import asyncio
from datetime import datetime, timedelta, timezone
import logging
import uuid
from typing import Any, Dict, List, Optional

import activities as a

logger = logging.getLogger("orchestrator.workflows")

# Temporal imports guarded for standalone execution
try:
    from temporalio import workflow
    from temporalio.common import RetryPolicy
    RETRY = RetryPolicy(initial_interval=timedelta(seconds=5), backoff_coefficient=2.0, maximum_attempts=5)
    SHORT = dict(start_to_close_timeout=timedelta(minutes=5), retry_policy=RETRY)
except ImportError:
    # Minimal mock decorator for offline testing without temporalio installed
    class _MockWorkflow:
        def defn(self, **kwargs):
            return lambda cls: cls
        def run(self, fn):
            return fn
        def execute_activity(self, fn, *args, **kwargs):
            return fn(*args)
        def execute_child_workflow(self, *args, **kwargs):
            pass
    workflow = _MockWorkflow()
    RETRY = None
    SHORT = {}


# ==============================================================================
# SECTION 6.1 INVESTIGATE ASSET WORKFLOW
# ==============================================================================

@workflow.defn(name="InvestigateAssetWorkflow")
class InvestigateAssetWorkflow:
    """Core workflow running 10-step investigation pipeline for serious findings."""

    @workflow.run
    async def run(self, finding_id: str) -> Dict[str, Any]:
        logger.info("Executing InvestigateAssetWorkflow for finding %s", finding_id)

        # Step 13: Load context
        ctx = await a.load_context(finding_id)

        # Steps 14-15: Run quantification investigator agent
        inv = await a.run_quantification_agent_investigate(ctx)
        if not inv.get("confirmed", True):
            await a.close_clean(finding_id)
            return {"finding_id": finding_id, "status": "clean"}

        # Step 16: Compliance agent + OPA policy check
        verdicts = await a.run_compliance_agent(inv)

        # Step 17: Sandbox verification (Dagger)
        proof = None
        if inv.get("needs_proof"):
            proof = await a.sandbox_verify(inv)

        # Step 18: FAIR quantification in ₹
        risk = await a.run_quantification_agent_fair({"inv": inv, "proof": proof})

        # Step 19: Prioritization
        rank = await a.run_prioritization_agent(ctx.get("tenant_id", "default"))

        state = {
            "inv": inv,
            "verdicts": verdicts,
            "proof": proof,
            "risk": risk,
            "rank": rank
        }

        # Step 20: Write final RiskState to graph and risk_queue table
        await a.write_final_state(state)

        # Steps 21-22: Build attested evidence pack (PDF + OpenTimestamps)
        pack = await a.build_evidence_pack(state)

        # Step 23: Publish alert over Kafka alerts.outbound
        await a.notify({**state, "pack": pack})

        finding_rank = rank.get(finding_id, 1) if isinstance(rank, dict) else 1
        return {
            "finding_id": finding_id,
            "eal_inr": risk.get("eal_inr", 0.0),
            "rank": finding_rank,
            "status": "completed",
            "evidence_url": pack.get("evidence_url")
        }


# ==============================================================================
# SECTION 6.4 RE-VERIFICATION AFTER A FIX
# ==============================================================================

@workflow.defn(name="ReverifyFindingWorkflow")
class ReverifyFindingWorkflow:
    """Triggered when a new commit touches a file with an open finding."""

    @workflow.run
    async def run(self, finding_id: str, new_sha: str) -> Dict[str, Any]:
        logger.info("Executing ReverifyFindingWorkflow for finding %s at %s", finding_id, new_sha)
        ctx = await a.load_context(finding_id)
        ctx["commit_sha"] = new_sha

        inv = await a.run_quantification_agent_investigate(ctx)
        proof = await a.sandbox_verify(inv)

        # If exploit no longer reproduces, mark fixed
        if not proof.get("exploitable", False):
            inv["status"] = "fixed"

        risk = await a.run_quantification_agent_fair({"inv": inv, "proof": proof})
        rank = await a.run_prioritization_agent(ctx.get("tenant_id", "default"))
        state = {"inv": inv, "verdicts": {}, "proof": proof, "risk": risk, "rank": rank}

        await a.write_final_state(state)
        pack = await a.build_evidence_pack(state)
        await a.notify({**state, "pack": pack})

        return {"finding_id": finding_id, "status": "fixed" if not proof.get("exploitable") else "still_open"}


# ==============================================================================
# SECTION 11.3 ONBOARDING WORKFLOW
# ==============================================================================

@workflow.defn(name="OnboardingWorkflow")
class OnboardingWorkflow:
    """Full onboarding scan and prioritized batch investigation."""

    @workflow.run
    async def run(self, repo_id: str) -> Dict[str, Any]:
        logger.info("Executing OnboardingWorkflow for repository: %s", repo_id)
        job = await a.start_full_scan(repo_id)
        await a.wait_for_scan(job)

        queue = await a.rank_for_investigation(repo_id)
        limit = queue.get("max_parallel", 5)
        finding_ids = queue.get("finding_ids", [])

        # Process in batches
        for i in range(0, len(finding_ids), limit):
            batch = finding_ids[i:i + limit]
            tasks = [InvestigateAssetWorkflow().run(fid) for fid in batch]
            await asyncio.gather(*tasks)

        report = await a.build_baseline_report(repo_id)
        await a.mark_onboarded(repo_id)
        return report


# ==============================================================================
# COMPATIBILITY SCANNER ORCHESTRATION FUNCTIONS
# ==============================================================================

def ai_agent_select_tools(target: str, target_type: Optional[str] = None) -> Dict[str, Any]:
    t = target.lower().strip()
    if target_type:
        t_type = target_type.lower()
        if "repo" in t_type or "code" in t_type:
            return {
                "agent_name": "AI Tool Selection & Prioritization Agent",
                "selected_tools": ["semgrep", "checkov"],
                "reasoning": f"Asset '{target}' identified as source code repository. Selected Semgrep (SAST) and Checkov (IaC).",
                "confidence_score": 0.98,
                "target_category": "Source Code Repository"
            }
        if "image" in t_type or "container" in t_type:
            return {
                "agent_name": "AI Tool Selection & Prioritization Agent",
                "selected_tools": ["cosign", "falco"],
                "reasoning": f"Asset '{target}' identified as container. Selected Cosign and Falco.",
                "confidence_score": 0.97,
                "target_category": "Container & Pod"
            }
        if "web" in t_type or "url" in t_type:
            return {
                "agent_name": "AI Tool Selection & Prioritization Agent",
                "selected_tools": ["zap", "suricata"],
                "reasoning": f"Asset '{target}' identified as live API. Selected ZAP and Suricata.",
                "confidence_score": 0.96,
                "target_category": "Web Application & REST API"
            }

    if t.startswith("repo://") or "git" in t or "/" in t and not t.startswith("http"):
        return {
            "agent_name": "AI Tool Selection & Prioritization Agent",
            "selected_tools": ["semgrep", "checkov"],
            "reasoning": f"Target '{target}' detected as Git repository. Selected Semgrep and Checkov.",
            "confidence_score": 0.98,
            "target_category": "Source Code Repository"
        }
    elif t.startswith("image://") or t.startswith("k8s://") or ":" in t and ("v" in t or "latest" in t):
        return {
            "agent_name": "AI Tool Selection & Prioritization Agent",
            "selected_tools": ["cosign", "falco"],
            "reasoning": f"Target '{target}' detected as container. Selected Cosign and Falco.",
            "confidence_score": 0.97,
            "target_category": "Container Workload"
        }
    else:
        return {
            "agent_name": "AI Tool Selection & Prioritization Agent",
            "selected_tools": ["semgrep", "checkov", "cosign", "falco", "suricata", "zap"],
            "reasoning": f"Target '{target}' classified as multi-tier enterprise perimeter. Selected full suite.",
            "confidence_score": 0.92,
            "target_category": "Enterprise Perimeter"
        }


def determine_applicable_tools(target: str, target_type: Optional[str] = None) -> List[str]:
    decision = ai_agent_select_tools(target, target_type)
    return decision["selected_tools"]


async def run_security_scan_workflow(
    target: str,
    tools: Optional[List[str]] = None,
    target_type: Optional[str] = None
) -> Dict[str, Any]:
    workflow_id = f"wf_{uuid.uuid4().hex[:12]}"
    agent_decision = ai_agent_select_tools(target, target_type)
    selected_tools = tools or agent_decision["selected_tools"]

    tasks = [a.invoke_scanner(tool, target) for tool in selected_tools]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings = []
    tool_status = {}
    for tool_name, res in zip(selected_tools, results):
        if isinstance(res, Exception):
            tool_status[tool_name] = "FAILED"
        elif isinstance(res, dict):
            status = res.get("status", "unknown").upper()
            tool_status[tool_name] = status
            all_findings.extend(res.get("findings", []))

    total_exposure = sum(
        float(f.get("fair_exposure", {}).get("expected_annual_loss_inr", 0.0) if isinstance(f.get("fair_exposure"), dict) else (f.get("expected_annual_loss_inr") or 0.0))
        for f in all_findings
    )

    return {
        "workflow_id": workflow_id,
        "target": target,
        "tools_requested": selected_tools,
        "tool_status": tool_status,
        "total_findings": len(all_findings),
        "total_exposure_inr": total_exposure,
        "findings": all_findings,
        "status": "COMPLETED",
        "agent_decision": agent_decision
    }
