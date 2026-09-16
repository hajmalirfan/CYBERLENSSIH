# SecuriX Security Scan Layer — Prototype

6 independent FastAPI services sharing one normalized `Finding` schema.

```
                SecuriX Security Scan Layer
                    Common Finding Schema (shared/schemas/finding.py)
    Semgrep:8001 Checkov:8002 Cosign:8003 Falco:8004 Suricata:8005 ZAP:8006
                    -> Normalized Findings -> Kafka findings.raw (optional)
```

## Contract (every service)

- `GET /health` -> `{"status": "ok", "tool": "<name>"}`
- `POST /scan` with `{"target": "..."}` -> `{"scan_id","tool","target","findings","timestamp"}`
- `GET /results/{scan_id}` -> stored scan response

Target semantics differ per tool (important for review):

| Service | Target | Notes |
|---|---|---|
| Semgrep `:8001` | source dir e.g. `/workspace/demo` | `semgrep --config auto --json <target>` |
| Checkov `:8002` | IaC dir e.g. `/workspace/terraform` | `checkov -d <target> -o json` |
| Cosign `:8003` | image ref e.g. `ghcr.io/example/app:latest` | `cosign verify <target>`; info if valid, high if not |
| Falco `:8004` | `runtime` or path to JSON-lines event file | `falco -o json_output=true`; or parse file |
| Suricata `:8005` | `.pcap` path, `eve.json` path, or dir containing `eve.json` | `suricata -r <pcap>` then parse `eve.json` alerts |
| ZAP `:8006` | base URL e.g. `http://example-app:8080` | `zap-baseline.py -t <target> -J report -I` |

## Quickstart

```powershell
cd securix-prototype
docker compose up --build semgrep-service
Invoke-RestMethod -Uri http://localhost:8001/health
Invoke-RestMethod -Uri http://localhost:8001/scan -Method POST `
  -ContentType "application/json" -Body '{"target":"/workspace/demo"}'
```

Each service starts independently: `docker compose up <service-name>`.

## Tests

Unit tests mock the CLI (`subprocess.run`) so no tool binary is needed.
Test files share the basename `test_main.py`, so a full-repo run needs
`--import-mode=importlib` (per-service runs work with plain `pytest`):

```powershell
cd securix-prototype
python -m pytest --import-mode=importlib services/semgrep-service/tests services/checkov-service/tests services/cosign-service/tests services/falco-service/tests services/suricata-service/tests services/zap-service/tests -v
# or per service:
python -m pytest services/semgrep-service/tests -v
```

## Kafka (Phase 2)

Services best-effort publish normalized findings to `findings.raw` only when
`KAFKA_BOOTSTRAP_SERVERS` is set (e.g. `kafka:9092`). Uncomment the `kafka`
service in `docker-compose.yml` to enable. No service fails if Kafka is absent.
