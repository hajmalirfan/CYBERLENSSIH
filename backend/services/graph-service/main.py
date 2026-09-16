"""SecuriX Graph Service.

Consumes normalized findings from Kafka 'findings.raw', writes them to
PostgreSQL + Apache AGE knowledge graph, and exposes the Graph Query API
for the Backstage portal, AI agents, and reporting services.
"""
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure shared package is importable
try:
    from shared.graph.age_client import SecuriXGraphClient
    from shared.kafka.consumer import FindingConsumer
    from shared.schemas.finding import Finding
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from shared.graph.age_client import SecuriXGraphClient
    from shared.kafka.consumer import FindingConsumer
    from shared.schemas.finding import Finding

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("graph-service")

graph_client = SecuriXGraphClient()
kafka_consumer: Optional[FindingConsumer] = None


def handle_kafka_finding(finding_data: Dict[str, Any]):
    """Process message from Kafka topic findings.raw."""
    try:
        finding = Finding(**finding_data)
        res = graph_client.ingest_finding(finding)
        logger.info("Kafka finding ingested to graph: %s", res.get("finding_id"))
    except Exception as e:
        logger.error("Failed to ingest Kafka finding to graph: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Launch Kafka consumer background thread if enabled
    global kafka_consumer
    kafka_consumer = FindingConsumer(handler=handle_kafka_finding)
    kafka_consumer.start_background()
    yield
    # Shutdown
    if kafka_consumer:
        kafka_consumer.stop()


app = FastAPI(
    title="SecuriX Graph Service & Query API",
    description="Knowledge Graph connector between all 6 scanners and the Backstage portal.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class VerifyRequest(BaseModel):
    analyst_name: Optional[str] = "SecOps Analyst"


class CypherRequest(BaseModel):
    query: str


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "graph-service",
        "db_mode": "postgresql+age" if graph_client.use_pg else "sqlite_embedded",
    }


@app.get("/graph/risk-queue")
def get_risk_queue(limit: int = Query(50, ge=1, le=200)):
    """Primary portal endpoint: returns open findings ranked by ₹ financial exposure."""
    return graph_client.get_risk_queue(limit=limit)


@app.get("/graph/findings")
def get_findings(
    asset_id: Optional[str] = None,
    tool: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
):
    """Query findings with optional filters."""
    return graph_client.get_findings(asset_id=asset_id, tool=tool, severity=severity, limit=limit)


@app.get("/graph/asset/{asset_id:path}")
def get_asset_detail(asset_id: str):
    """Full trace of asset: which tool found each issue, FAIR breakdown in ₹, compliance controls."""
    detail = graph_client.get_asset_detail(asset_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")
    return detail


@app.get("/graph/compliance")
def get_compliance_summary():
    """OPA compliance verdicts aggregated across RBI, SEBI, ISO 27001, NIST CSF, and DPDP Act."""
    return graph_client.get_compliance_summary()


@app.get("/graph/stats")
def get_stats():
    """Platform metrics: total assets, total findings, total ₹ exposure, tool/severity distributions."""
    return graph_client.get_stats()


@app.post("/graph/findings/ingest")
def ingest_finding(finding: Finding):
    """Direct REST ingestion endpoint for findings from scanners or test suites."""
    result = graph_client.ingest_finding(finding)
    return result


@app.post("/graph/findings/{finding_id}/verify")
def verify_finding(finding_id: str, req: Optional[VerifyRequest] = None):
    """Toggle analyst verification status on a finding."""
    analyst = req.analyst_name if req else "SecOps Analyst"
    res = graph_client.verify_finding(finding_id, analyst_name=analyst)
    if not res.get("success"):
        raise HTTPException(status_code=404, detail=res.get("error", "Failed to verify"))
    return res


@app.post("/graph/cypher")
def run_cypher(req: CypherRequest):
    """Execute raw openCypher query against Apache AGE graph."""
    return graph_client.execute_cypher(req.query)
