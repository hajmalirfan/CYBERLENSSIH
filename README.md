# SecuriX — Real-Time Cyber Risk Quantification Platform

Smart India Hackathon 2026 · Fully Open-Source Prototype

---

## Architecture

```
 ┌────────────────────────────────────────────────────────────────┐
 │                       docker-compose.yml                      │
 ├──────────────────────────┬─────────────────────────────────────┤
 │       frontend/          │          backend/                   │
 │  ┌──────────────────┐    │  ┌─────────────────────────────┐   │
 │  │  Portal Server    │    │  │  shared/ (Finding schema,   │   │
 │  │  :3000             │    │  │  graph client, Kafka, auth)│   │
 │  │  static/index.html │    │  ├─────────────────────────────┤   │
 │  └──────────────────┘    │  │  services/                   │   │
 │                           │  │    semgrep-service   :8001   │   │
 │                           │  │    checkov-service   :8002   │   │
 │                           │  │    cosign-service    :8003   │   │
 │                           │  │    falco-service     :8004   │   │
 │                           │  │    suricata-service  :8005   │   │
 │                           │  │    zap-service       :8006   │   │
 │                           │  │    graph-service     :8010   │   │
 │                           │  │    temporal-orch.    :8011   │   │
 │                           │  │    evidence-gen.     :8012   │   │
 │                           │  │    agent-mesh        :8013   │   │
 │                           │  └─────────────────────────────┘   │
 └──────────────────────────┴─────────────────────────────────────┘
         Infra: PostgreSQL+AGE :5432 │ Kafka :9092 │ Temporal :7233
                LiteLLM :4000 │ Keycloak :8080
```

## Folder Structure

```
cyberlens-securix/
├── frontend/               # Portal UI & BFF server
│   ├── server.py           # FastAPI proxy + static server
│   ├── static/index.html   # Single-page Backstage-style dashboard
│   ├── shared/             # Copy of shared libs (graph fallback)
│   ├── Dockerfile
│   └── requirements.txt
├── backend/                # All microservices
│   ├── shared/             # Common modules
│   │   ├── schemas/        # Finding schema (Pydantic)
│   │   ├── graph/          # AGE graph client
│   │   ├── kafka/          # Kafka producer helper
│   │   ├── auth/           # Keycloak JWT middleware
│   │   └── llm/            # LiteLLM client wrapper
│   ├── services/           # 10 microservices
│   │   ├── semgrep-service/
│   │   ├── checkov-service/
│   │   ├── cosign-service/
│   │   ├── falco-service/
│   │   ├── suricata-service/
│   │   ├── zap-service/
│   │   ├── graph-service/
│   │   ├── temporal-orchestrator/
│   │   ├── evidence-generator/
│   │   └── agent-mesh/
│   └── requirements-dev.txt
├── config/                 # LiteLLM config
├── deploy/                 # Keycloak realm export
├── init-scripts/           # PostgreSQL+AGE init SQL
├── targets/                # Sample scan targets
├── docker-compose.yml      # Full stack orchestration
└── README.md
```

## Contract (every scanner service)

- `GET /health` → `{"status": "ok", "tool": "<name>"}`
- `POST /scan` with `{"target": "..."}` → `{"scan_id","tool","target","findings","timestamp"}`
- `GET /results/{scan_id}` → stored scan response

Target semantics differ per tool:

| Service | Target | Notes |
|---|---|---|
| Semgrep `:8001` | source dir e.g. `/workspace/demo` | `semgrep --config auto --json <target>` |
| Checkov `:8002` | IaC dir e.g. `/workspace/terraform` | `checkov -d <target> -o json` |
| Cosign `:8003` | image ref e.g. `ghcr.io/example/app:latest` | `cosign verify <target>`; info if valid, high if not |
| Falco `:8004` | `runtime` or path to JSON-lines event file | `falco -o json_output=true`; or parse file |
| Suricata `:8005` | `.pcap` path, `eve.json` path, or dir containing `eve.json` | `suricata -r <pcap>` then parse `eve.json` alerts |
| ZAP `:8006` | base URL e.g. `http://example-app:8080` | `zap-baseline.py -t <target> -J report -I` |

## Quickstart

### Option 1 — Full Docker Stack

```powershell
# From project root
docker compose up --build
```

Portal at http://localhost:3000, individual services on their ports above.

### Option 2 — Single Service

```powershell
docker compose up --build semgrep-service
Invoke-RestMethod -Uri http://localhost:8001/health
Invoke-RestMethod -Uri http://localhost:8001/scan -Method POST `
  -ContentType "application/json" -Body '{"target":"/workspace/demo"}'
```

### Option 3 — Local Dev (no Docker)

```powershell
# Create & activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dev deps
pip install -r backend/requirements-dev.txt

# Run a single service
cd backend
uvicorn services.semgrep-service.main:app --port 8001 --reload
```

## Tests

```powershell
# Activate venv first
.\.venv\Scripts\Activate.ps1

# Run all backend tests
python -m pytest --import-mode=importlib `
  backend/services/semgrep-service/tests `
  backend/services/checkov-service/tests `
  backend/services/cosign-service/tests `
  backend/services/falco-service/tests `
  backend/services/suricata-service/tests `
  backend/services/zap-service/tests `
  backend/services/graph-service/tests `
  backend/services/agent-mesh/tests `
  backend/services/evidence-generator/tests `
  backend/services/temporal-orchestrator/tests `
  -v

# Or per service:
python -m pytest backend/services/semgrep-service/tests -v
```

## Kafka (Phase 2)

Services best-effort publish normalized findings to `findings.raw` only when
`KAFKA_BOOTSTRAP_SERVERS` is set (e.g. `kafka:9092`). No service fails if Kafka is absent.

## Team Structure (SIH 2026)

| # | Member | Owns (Tool) | Also Owns (Shared Infra) |
|---|---|---|---|
| 1 | Code Security | Semgrep, Checkov | Knowledge Graph (PostgreSQL + AGE) |
| 2 | Supply Chain & CI/CD | Cosign/Sigstore | CI/CD pipeline (Trivy, Gitleaks, tfsec, gates) |
| 3 | Runtime & Network | Falco, Suricata | Temporal Orchestrator |
| 4 | Web App Security | OWASP ZAP | FAIR Engine (₹ quantification) |
| 5 | AI/ML & Agent Mesh | LiteLLM + Agents | Agent Mesh, OPA guardrails |
| 6 | Frontend & Compliance | Portal, Evidence | Backstage portal, evidence generation |
