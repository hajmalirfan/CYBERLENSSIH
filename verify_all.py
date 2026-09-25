"""SecuriX Full Verification Script."""
import sys
import os
import py_compile

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(ROOT, "backend")
SERVICES = os.path.join(BACKEND, "services")
sys.path.insert(0, BACKEND)
sys.path.insert(0, ROOT)

results = []

def check(label, fn):
    try:
        result = fn()
        msg = result if isinstance(result, str) else "OK"
        print(f"  [PASS] {label}: {msg}")
        results.append((label, True, msg))
    except Exception as e:
        err = str(e)
        print(f"  [FAIL] {label}: {err}")
        results.append((label, False, err))

print("\n" + "="*60)
print("  SecuriX Verification Suite")
print("="*60)

# ── 1. SHARED SCHEMAS ─────────────────────────────────────────
print("\n[1] Shared Schemas")

def check_finding_schema():
    from shared.schemas.finding import Finding, Severity, Alert, RiskState, ScanJob
    f = Finding(
        source="semgrep", rule_id="test.rule", severity="critical",
        description="Test finding", file_path="src/main.py", line_number=42,
        tenant_id="tenant-1", repo_id="repo://test"
    )
    assert f.severity == Severity.CRITICAL
    assert f.finding_id is not None
    assert f.tool == "semgrep"
    assert f.file == "src/main.py"
    assert f.line == 42
    return "Finding ID=%s... severity=%s" % (f.finding_id[:8], f.severity.value)

check("Finding schema + field harmonization", check_finding_schema)

def check_alert_schema():
    from shared.schemas.finding import Alert
    a = Alert(finding_id="f1", asset="repo://test", title="Test Alert",
              severity="high", eal_inr=1500000.0, rank=1)
    assert a.tenant_id == "default"
    return "Alert: %s" % a.title

check("Alert schema", check_alert_schema)

def check_risk_state_schema():
    from shared.schemas.finding import RiskState
    r = RiskState(finding_id="f2", eal_inr=2000000.0, rank=2)
    return "RiskState eal_inr=Rs.%.0f" % r.eal_inr

check("RiskState schema", check_risk_state_schema)

def check_scan_job_schema():
    from shared.schemas.finding import ScanJob
    j = ScanJob(repo_id="repo://fintech/payment-gateway", mode="full")
    assert j.status == "queued"
    return "ScanJob ID=%s..." % j.job_id[:8]

check("ScanJob schema", check_scan_job_schema)

# ── 2. GRAPH CLIENT ───────────────────────────────────────────
print("\n[2] Graph Client (PostgreSQL+AGE / SQLite fallback)")

def check_graph_client_init():
    from shared.graph.age_client import SecuriXGraphClient
    client = SecuriXGraphClient()
    return "mode=%s" % ("PostgreSQL" if client.use_pg else "SQLite fallback")

check("Graph client init", check_graph_client_init)

def check_graph_client_get_assets():
    from shared.graph.age_client import SecuriXGraphClient
    client = SecuriXGraphClient()
    assets = client.get_assets()
    return "%d seeded assets found" % len(assets)

check("Graph client get_assets()", check_graph_client_get_assets)

def check_graph_client_get_findings():
    from shared.graph.age_client import SecuriXGraphClient
    client = SecuriXGraphClient()
    findings = client.get_findings()
    return "%d seeded findings found" % len(findings)

check("Graph client get_findings()", check_graph_client_get_findings)

def check_graph_client_ingest():
    from shared.graph.age_client import SecuriXGraphClient
    from shared.schemas.finding import Finding
    client = SecuriXGraphClient()
    f = Finding(source="semgrep", rule_id="test.ingest", severity="high",
                description="Ingest test", tenant_id="test-tenant")
    result = client.ingest_finding(f)
    assert result.get("finding_id") is not None
    return "Ingested finding_id=%s..." % result["finding_id"][:8]

check("Graph client ingest_finding()", check_graph_client_ingest)

def check_graph_client_risk_queue():
    from shared.graph.age_client import SecuriXGraphClient
    client = SecuriXGraphClient()
    queue = client.get_risk_queue()
    return "risk_queue has %d entries" % len(queue)

check("Graph client get_risk_queue()", check_graph_client_risk_queue)

def check_graph_stats():
    from shared.graph.age_client import SecuriXGraphClient
    client = SecuriXGraphClient()
    stats = client.get_graph_stats()
    return "stats keys=%s" % list(stats.keys())

check("Graph client get_graph_stats()", check_graph_stats)

# ── 3. KAFKA ─────────────────────────────────────────────────
print("\n[3] Kafka (graceful offline if broker not running)")

def check_kafka_producer():
    from shared.kafka.producer import FindingProducer
    p = FindingProducer()
    return "enabled=%s broker=%s" % (p._enabled, "connected" if p._enabled else "offline-OK")

check("Kafka producer init", check_kafka_producer)

def check_kafka_consumer():
    from shared.kafka.consumer import FindingConsumer
    c = FindingConsumer(handler=lambda d: None)
    return "consumer ready, bootstrap='%s'" % (c.bootstrap or "not-configured-OK")

check("Kafka consumer init", check_kafka_consumer)

# ── 4. AUTH ───────────────────────────────────────────────────
print("\n[4] Auth (Keycloak / Mock)")

def check_auth():
    from shared.auth.keycloak import current_user, require
    return "current_user and require importable"

check("Auth keycloak module import", check_auth)

# ── 5. LLM CLIENT ────────────────────────────────────────────
print("\n[5] LLM Gateway Client")

def check_llm():
    from shared.llm.client import SecuriXLLMClient
    c = SecuriXLLMClient()
    return "base_url=%s" % c.base_url

check("LLM client init", check_llm)

# ── 6. AGENT MESH ENGINES ─────────────────────────────────────
print("\n[6] Agent Mesh (FAIR + OPA + Prioritizer)")

def check_fair():
    sys.path.insert(0, os.path.join(SERVICES, "agent-mesh"))
    from pyfair_engine import FAIRSimulationEngine
    eng = FAIRSimulationEngine()
    result = eng.simulate(severity="critical", criticality="CRITICAL", iterations=100)
    assert result["expected_annual_loss_inr"] > 0
    return "critical EAL=%s" % result["formatted_inr"].replace("₹", "Rs. ")

check("FAIR Monte Carlo simulation", check_fair)

def check_opa():
    sys.path.insert(0, os.path.join(SERVICES, "agent-mesh"))
    from opa_engine import OPAComplianceEngine
    eng = OPAComplianceEngine()
    finding = {
        "title": "Hardcoded JWT Secret in source code",
        "severity": "critical",
        "rule_id": "jwt-secret",
        "description": "JWT token secret hardcoded"
    }
    verdicts = eng.evaluate(finding)
    fails = [v for v in verdicts if v["status"] == "FAIL"]
    return "%d verdicts, %d FAIL" % (len(verdicts), len(fails))

check("OPA compliance evaluation", check_opa)

def check_prioritizer():
    sys.path.insert(0, os.path.join(SERVICES, "agent-mesh"))
    from prioritizer import PrioritizationAgent
    agent = PrioritizationAgent()
    finding = {
        "severity": "critical",
        "criticality": "CRITICAL",
        "fair_exposure": {"expected_annual_loss_inr": 5000000.0}
    }
    result = agent.prioritize_finding(finding)
    assert "P1" in result["priority_tier"]
    return "tier=%s, score=%s" % (result["priority_tier"], result["composite_score"])

check("Prioritization Agent", check_prioritizer)

# ── 7. GRAPH SERVICE FASTAPI ──────────────────────────────────
print("\n[7] Graph Service API")

def check_graph_service():
    import importlib.util
    graph_svc = os.path.join(SERVICES, "graph-service")
    sys.path.insert(0, graph_svc)
    spec = importlib.util.spec_from_file_location("graph_main", os.path.join(graph_svc, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    app = mod.app
    routes = [r.path for r in app.routes]
    return "%d routes registered" % len(routes)

check("Graph service FastAPI app", check_graph_service)

# ── 8. AGENT MESH FASTAPI ─────────────────────────────────────
print("\n[8] Agent Mesh API")

def check_agent_mesh():
    import importlib.util
    agent_dir = os.path.join(SERVICES, "agent-mesh")
    sys.path.insert(0, agent_dir)
    spec = importlib.util.spec_from_file_location("agent_main", os.path.join(agent_dir, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    app = mod.app
    routes = [r.path for r in app.routes if "agent" in r.path]
    return "agent routes: %s" % routes

check("Agent mesh FastAPI app", check_agent_mesh)

# ── 9. SCANNER SERVICES SYNTAX ────────────────────────────────
print("\n[9] Scanner Services (syntax check)")

scanner_files = [
    ("cosign-service",   "main.py"),
    ("semgrep-service",  "main.py"),
    ("checkov-service",  "main.py"),
    ("falco-service",    "main.py"),
    ("suricata-service", "main.py"),
    ("zap-service",      "main.py"),
]

for svc, fname in scanner_files:
    fpath = os.path.join(SERVICES, svc, fname)
    def make_check(p, name):
        def _check():
            if not os.path.exists(p):
                raise FileNotFoundError("%s not found" % name)
            py_compile.compile(p, doraise=True)
            return "syntax OK"
        return _check
    check("%s/%s" % (svc, fname), make_check(fpath, "%s/%s" % (svc, fname)))

# ── SUMMARY ───────────────────────────────────────────────────
print("\n" + "="*60)
total  = len(results)
passed = sum(1 for _, ok, _ in results if ok)
failed = total - passed

print("  TOTAL : %d" % total)
print("  PASSED: %d" % passed)
if failed:
    print("  FAILED: %d" % failed)
    print("\n  Failed checks:")
    for label, ok, msg in results:
        if not ok:
            print("    - %s: %s" % (label, msg))
else:
    print("  ALL CHECKS PASSED!")
print("="*60 + "\n")
sys.exit(0 if failed == 0 else 1)
