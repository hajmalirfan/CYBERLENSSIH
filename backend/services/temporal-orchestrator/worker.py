"""Temporal Worker Service.

Section 6.3 of SecuriX Implementation Guide.
Runs the investigations task queue worker hosting InvestigateAssetWorkflow,
ReverifyFindingWorkflow, OnboardingWorkflow, and their activities.
"""
import asyncio
import logging
import os
import sys

# Ensure local imports work
sys.path.insert(0, os.path.dirname(__file__))

import activities as a
from workflows import InvestigateAssetWorkflow, ReverifyFindingWorkflow, OnboardingWorkflow

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("orchestrator.worker")

TEMPORAL_ADDRESS = os.getenv("TEMPORAL_ADDRESS", "temporal:7233")


async def main():
    try:
        from temporalio.client import Client
        from temporalio.worker import Worker

        logger.info("Connecting to Temporal server at %s...", TEMPORAL_ADDRESS)
        client = await Client.connect(TEMPORAL_ADDRESS, namespace="default")

        worker = Worker(
            client,
            task_queue="investigations",
            workflows=[InvestigateAssetWorkflow, ReverifyFindingWorkflow, OnboardingWorkflow],
            activities=[
                a.load_context,
                a.run_quantification_agent_investigate,
                a.run_compliance_agent,
                a.sandbox_verify,
                a.run_quantification_agent_fair,
                a.run_prioritization_agent,
                a.write_final_state,
                a.build_evidence_pack,
                a.notify,
                a.close_clean,
                a.start_full_scan,
                a.wait_for_scan,
                a.rank_for_investigation,
                a.build_baseline_report,
                a.mark_onboarded,
                a.invoke_scanner,
            ],
            max_concurrent_activities=20,
        )
        logger.info("Temporal Worker started on task_queue='investigations'.")
        await worker.run()
    except Exception as e:
        logger.warning("Temporal Worker could not start (%s). Activities available via REST orchestrator.", e)


if __name__ == "__main__":
    asyncio.run(main())
