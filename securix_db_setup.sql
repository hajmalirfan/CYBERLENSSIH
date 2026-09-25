-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  SecuriX Knowledge Graph — Complete Database Setup                          ║
-- ║  Smart India Hackathon 2026 · Cyber Risk Quantification Platform            ║
-- ║                                                                              ║
-- ║  ARCHITECTURE (data flow):                                                   ║
-- ║  1. User triggers scan  → temporal-orchestrator creates workflow_run         ║
-- ║  2. AI Agent picks tools → logs each decision to agent_tool_decisions        ║
-- ║  3. Each tool runs → emits finding to Kafka topic: findings.raw              ║
-- ║  4. graph-service consumes Kafka → writes findings + kafka_events            ║
-- ║  5. agent-mesh runs PyFair (INR risk) + OPA (compliance) per finding        ║
-- ║  6. Frontend reads findings + compliance_verdicts for Risk Queue             ║
-- ║                                                                              ║
-- ║  HOW TO RUN IN pgAdmin:                                                      ║
-- ║    1. pgAdmin → right-click your server → Connect                           ║
-- ║    2. Databases → Create → Database → name: securix_db → Save               ║
-- ║    3. Click securix_db → Tools → Query Tool                                 ║
-- ║    4. Paste this entire file → F5 (Execute All)                              ║
-- ║                                                                              ║
-- ║  Local credentials: postgres / postgres @ localhost:5432                     ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION A  Apache AGE Graph Extension (OPTIONAL)
-- Skip if Apache AGE is not installed on your PostgreSQL.
-- All relational tables in Section B work without AGE.
-- ─────────────────────────────────────────────────────────────────────────────
-- CREATE EXTENSION IF NOT EXISTS age;
-- LOAD 'age';
-- SET search_path = ag_catalog, "$user", public;
-- DO $$
-- BEGIN
--     IF NOT EXISTS (SELECT 1 FROM ag_graph WHERE name = 'securix_graph') THEN
--         PERFORM create_graph('securix_graph');
--     END IF;
-- END $$;


-- ═════════════════════════════════════════════════════════════════════════════
-- SECTION B  Core Relational Schema (always run this)
-- ═════════════════════════════════════════════════════════════════════════════

-- B0. RELATIONAL TABLES REQUIRED BY SECURIX IMPLEMENTATION GUIDE (Section 3.4)
CREATE TABLE IF NOT EXISTS raw_outputs (
    finding_id   VARCHAR(255) PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    payload      JSONB,            -- null when stored in MinIO
    minio_path   TEXT,             -- used when payload > 256 KB
    created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS risk_queue (          -- flat copy of RiskState for Grafana/Metabase
    finding_id   VARCHAR(255) PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    asset_id     TEXT,
    title        TEXT,
    eal_inr      NUMERIC,
    p90_loss_inr NUMERIC,
    rank         INT,
    verdicts     JSONB,            -- {"RBI-AC-04": "FAIL", ...}
    evidence_url TEXT,
    status       TEXT,             -- open | verified | fixed
    updated_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id       VARCHAR(255) PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    repo_id      TEXT NOT NULL,
    mode         TEXT NOT NULL,    -- full | incremental
    commit_sha   TEXT,
    status       TEXT,             -- queued | running | done | failed
    tools_run    TEXT[],
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ
);

-- B1. ASSETS — monitored attack-surface targets
--     Written by: temporal-orchestrator when a scan is first triggered
CREATE TABLE IF NOT EXISTS assets (
    asset_id    VARCHAR(255) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    asset_type  VARCHAR(64)  NOT NULL,
        -- repo | container_image | iac_source | web_endpoint | host
    criticality VARCHAR(32)  DEFAULT 'HIGH',
        -- CRITICAL | HIGH | MEDIUM | LOW
    owner       VARCHAR(128) DEFAULT 'SecOps',
    metadata    JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP
);

-- B2. WORKFLOW_RUNS — one row per AI-agent orchestration cycle
--     Written by: temporal-orchestrator (workflows.py)
--     agent_reasoning = LLM or heuristic explanation of tool selection
CREATE TABLE IF NOT EXISTS workflow_runs (
    workflow_id        VARCHAR(128) PRIMARY KEY,
    target             VARCHAR(512) NOT NULL,
    target_type        VARCHAR(64),
        -- repo | container | web | host | all
    tools_requested    TEXT[],
    tools_completed    TEXT[],
    tool_status        JSONB        DEFAULT '{}',
        -- e.g. {"semgrep":"COMPLETED","zap":"FAILED"}
    total_findings     INT          DEFAULT 0,
    total_exposure_inr NUMERIC(15,2) DEFAULT 0.0,
    status             VARCHAR(32)  DEFAULT 'RUNNING',
        -- RUNNING | COMPLETED | FAILED | PARTIAL
    agent_reasoning    TEXT,
    agent_model_used   VARCHAR(64)  DEFAULT 'heuristic_fallback',
        -- gpt-4o-mini | gemini-pro | heuristic_fallback
    triggered_by       VARCHAR(64)  DEFAULT 'api',
        -- api | ci_webhook | scheduled | frontend_button
    started_at         TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP,
    completed_at       TIMESTAMPTZ
);

-- B3. AGENT_TOOL_DECISIONS — audit log of every AI tool-selection decision
--     determine_applicable_tools() in workflows.py logs one row per tool
CREATE TABLE IF NOT EXISTS agent_tool_decisions (
    id            SERIAL       PRIMARY KEY,
    workflow_id   VARCHAR(128) REFERENCES workflow_runs(workflow_id) ON DELETE CASCADE,
    tool          VARCHAR(64)  NOT NULL,
        -- semgrep | checkov | cosign | falco | zap | suricata
    decision      VARCHAR(32)  NOT NULL,
        -- SELECTED | SKIPPED
    reason        TEXT,        -- AI explanation of why this tool was chosen/skipped
    target_signal VARCHAR(128),-- signal used: "starts with repo://" etc.
    decided_at    TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP
);

-- B4. SCANS — one row per tool invocation within a workflow
--     Written by: temporal-orchestrator activities.py (invoke_scanner)
CREATE TABLE IF NOT EXISTS scans (
    scan_id            VARCHAR(128) PRIMARY KEY,
    workflow_id        VARCHAR(128) REFERENCES workflow_runs(workflow_id) ON DELETE SET NULL,
    asset_id           VARCHAR(255) REFERENCES assets(asset_id)          ON DELETE SET NULL,
    target             VARCHAR(512) NOT NULL,
    tool               VARCHAR(64)  NOT NULL,
        -- semgrep | checkov | cosign | falco | zap | suricata
    status             VARCHAR(32)  DEFAULT 'RUNNING',
        -- RUNNING | COMPLETED | FAILED | SKIPPED
    findings_count     INT          DEFAULT 0,
    total_exposure_inr NUMERIC(15,2) DEFAULT 0.0,
    error_message      TEXT,
    started_at         TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP,
    completed_at       TIMESTAMPTZ
);

-- B5. FINDINGS — core output of every scanner tool
--     Written by: graph-service (Kafka consumer)
--     FAIR INR columns enriched by: agent-mesh PyFair engine
CREATE TABLE IF NOT EXISTS findings (
    finding_id               VARCHAR(255) PRIMARY KEY,
    scan_id                  VARCHAR(128) REFERENCES scans(scan_id)    ON DELETE SET NULL,
    asset_id                 VARCHAR(255) REFERENCES assets(asset_id)  ON DELETE CASCADE,
    tool                     VARCHAR(64)  NOT NULL,
    rule_id                  VARCHAR(255),
    title                    VARCHAR(512) NOT NULL,
    severity                 VARCHAR(32)  NOT NULL,
        -- critical | high | medium | low | info
    description              TEXT,
    file_path                TEXT,
    line_number              INT,
    category                 VARCHAR(64)  DEFAULT 'vulnerability',
        -- code | infrastructure | supply-chain | web | runtime | network
    -- FAIR Risk Quantification (filled by agent-mesh)
    expected_annual_loss_inr NUMERIC(15,2) DEFAULT 0.0,   -- EAL = LEF x LM
    primary_loss_inr         NUMERIC(15,2) DEFAULT 0.0,   -- IR / forensics
    secondary_loss_inr       NUMERIC(15,2) DEFAULT 0.0,   -- fines / reputation
    loss_event_frequency     NUMERIC(6,4)  DEFAULT 0.10,  -- events per year
    loss_magnitude_inr       NUMERIC(15,2) DEFAULT 500000.0, -- per-event INR
    -- SecOps Verification
    verified                 BOOLEAN       DEFAULT FALSE,
    verified_by              VARCHAR(128),
    verified_at              TIMESTAMPTZ,
    -- Raw Tool Output
    raw_output               JSONB         DEFAULT '{}',
    evidence                 TEXT,
    remediation              TEXT,
    scanned_at               TIMESTAMPTZ   DEFAULT CURRENT_TIMESTAMP
);

-- B6. COMPLIANCE_VERDICTS — OPA Rego policy evaluation per finding
--     Written by: agent-mesh OPAComplianceEngine
--     Regulations: RBI | SEBI | ISO27001 | NIST_CSF | DPDP | CERT_IN
CREATE TABLE IF NOT EXISTS compliance_verdicts (
    id           SERIAL       PRIMARY KEY,
    finding_id   VARCHAR(255) REFERENCES findings(finding_id) ON DELETE CASCADE,
    regulation   VARCHAR(64)  NOT NULL,
    control_id   VARCHAR(128) NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    status       VARCHAR(32)  NOT NULL,
        -- PASS | FAIL | NOT_APPLICABLE
    rationale    TEXT,
    evaluated_at TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP
);

-- B7. KAFKA_EVENTS — audit log of every message on findings.raw topic
--     Written by: graph-service after consuming each Kafka message
CREATE TABLE IF NOT EXISTS kafka_events (
    id            BIGSERIAL    PRIMARY KEY,
    topic         VARCHAR(128) DEFAULT 'findings.raw',
    partition_num INT,
    kafka_offset  BIGINT,
    key           VARCHAR(255),
    payload       JSONB        NOT NULL,
    producer      VARCHAR(64),
    consumed_at   TIMESTAMPTZ  DEFAULT CURRENT_TIMESTAMP,
    processed     BOOLEAN      DEFAULT FALSE,
    error         TEXT
);


-- ═════════════════════════════════════════════════════════════════════════════
-- SECTION C  Performance Indexes
-- ═════════════════════════════════════════════════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_findings_exposure     ON findings(expected_annual_loss_inr DESC);
CREATE INDEX IF NOT EXISTS idx_findings_asset        ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_tool         ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_severity     ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_scan         ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_verified     ON findings(verified);
CREATE INDEX IF NOT EXISTS idx_compliance_reg        ON compliance_verdicts(regulation, status);
CREATE INDEX IF NOT EXISTS idx_compliance_finding    ON compliance_verdicts(finding_id);
CREATE INDEX IF NOT EXISTS idx_workflow_status       ON workflow_runs(status);
CREATE INDEX IF NOT EXISTS idx_scans_workflow        ON scans(workflow_id);
CREATE INDEX IF NOT EXISTS idx_scans_status          ON scans(status);
CREATE INDEX IF NOT EXISTS idx_kafka_processed       ON kafka_events(processed, consumed_at);
CREATE INDEX IF NOT EXISTS idx_kafka_producer        ON kafka_events(producer);
CREATE INDEX IF NOT EXISTS idx_agent_decisions_wf    ON agent_tool_decisions(workflow_id);


-- ═════════════════════════════════════════════════════════════════════════════
-- SECTION D  Seed Data (SIH 2026 Demo)
-- 4 assets, 1 workflow, 6 AI decisions, 6 scans,
-- 6 findings (one per tool), 18 compliance verdicts, 6 Kafka events
-- ═════════════════════════════════════════════════════════════════════════════

-- D1. Assets
INSERT INTO assets (asset_id, name, asset_type, criticality, owner) VALUES
    ('repo://fintech/payment-gateway',               'Payment Gateway Core',          'repo',            'CRITICAL', 'Payments Team'),
    ('image://registry.internal/checkout-api:v2.4',  'Checkout API Container',        'container_image', 'CRITICAL', 'Core Banking Team'),
    ('iac://cloud/aws-production-vpc',               'AWS Production VPC Terraform',  'iac_source',      'HIGH',     'Cloud Platform Team'),
    ('url://api.fintech.internal/v1/transfer',       'Fund Transfer API Endpoint',    'web_endpoint',    'CRITICAL', 'API Security Team')
ON CONFLICT (asset_id) DO NOTHING;

-- D2. Workflow Run (AI agent orchestration cycle)
INSERT INTO workflow_runs (
    workflow_id, target, target_type,
    tools_requested, tools_completed, tool_status,
    total_findings, total_exposure_inr,
    status, agent_reasoning, agent_model_used, triggered_by,
    started_at, completed_at
) VALUES (
    'wf_demo_001',
    'fintech-payment-platform',
    'all',
    ARRAY['semgrep','checkov','cosign','falco','zap','suricata'],
    ARRAY['semgrep','checkov','cosign','falco','zap','suricata'],
    '{"semgrep":"COMPLETED","checkov":"COMPLETED","cosign":"COMPLETED","falco":"COMPLETED","zap":"COMPLETED","suricata":"COMPLETED"}',
    6, 19570000.00, 'COMPLETED',
    'Target fintech-payment-platform exposes all four attack surfaces: source code (repo), IaC Terraform, container images, and live HTTP API endpoints. Full-scan mode selected. SAST (semgrep) and IaC (checkov) cover the code and infrastructure layer. Supply-chain integrity (cosign) and runtime behaviour (falco) cover the container layer. DAST (zap) and network monitoring (suricata) cover the live endpoint layer. All 6 tools selected. Total estimated annual exposure: INR 1,95,70,000.',
    'heuristic_fallback',
    'api',
    NOW() - INTERVAL '12 minutes',
    NOW() - INTERVAL '3 minutes'
) ON CONFLICT (workflow_id) DO NOTHING;

-- D3. AI Agent Tool Decisions
INSERT INTO agent_tool_decisions (workflow_id, tool, decision, reason, target_signal) VALUES
    ('wf_demo_001', 'semgrep',  'SELECTED', 'Source code repository detected — SAST scanning applicable.',               'target_type=all'),
    ('wf_demo_001', 'checkov',  'SELECTED', 'IaC Terraform files present — infrastructure policy scanning applicable.',  'target_type=all'),
    ('wf_demo_001', 'cosign',   'SELECTED', 'Container image references found — supply-chain signature check needed.',   'target_type=all'),
    ('wf_demo_001', 'falco',    'SELECTED', 'Containerised workload detected — runtime eBPF monitoring needed.',         'target_type=all'),
    ('wf_demo_001', 'zap',      'SELECTED', 'HTTP API endpoints exposed — DAST active scanning applicable.',             'target_type=all'),
    ('wf_demo_001', 'suricata', 'SELECTED', 'Live network traffic present — IDS network monitoring applicable.',         'target_type=all')
ON CONFLICT DO NOTHING;

-- D4. Scans (one per tool)
INSERT INTO scans (scan_id, workflow_id, asset_id, target, tool, status, findings_count, total_exposure_inr, started_at, completed_at) VALUES
    ('scan_demo_sast_01',    'wf_demo_001', 'repo://fintech/payment-gateway',               'repo://fintech/payment-gateway',               'semgrep',  'COMPLETED', 1, 4550000.00, NOW()-INTERVAL '11 min', NOW()-INTERVAL '9 min'),
    ('scan_demo_iac_02',     'wf_demo_001', 'iac://cloud/aws-production-vpc',               'iac://cloud/aws-production-vpc',               'checkov',  'COMPLETED', 1, 1820000.00, NOW()-INTERVAL '11 min', NOW()-INTERVAL '8 min'),
    ('scan_demo_supply_03',  'wf_demo_001', 'image://registry.internal/checkout-api:v2.4', 'image://registry.internal/checkout-api:v2.4',  'cosign',   'COMPLETED', 1, 1250000.00, NOW()-INTERVAL '11 min', NOW()-INTERVAL '7 min'),
    ('scan_demo_dast_04',    'wf_demo_001', 'url://api.fintech.internal/v1/transfer',       'url://api.fintech.internal/v1/transfer',       'zap',      'COMPLETED', 1, 5800000.00, NOW()-INTERVAL '11 min', NOW()-INTERVAL '6 min'),
    ('scan_demo_runtime_05', 'wf_demo_001', 'image://registry.internal/checkout-api:v2.4', 'image://registry.internal/checkout-api:v2.4',  'falco',    'COMPLETED', 1, 3400000.00, NOW()-INTERVAL '11 min', NOW()-INTERVAL '5 min'),
    ('scan_demo_net_06',     'wf_demo_001', 'url://api.fintech.internal/v1/transfer',       'url://api.fintech.internal/v1/transfer',       'suricata', 'COMPLETED', 1, 2750000.00, NOW()-INTERVAL '11 min', NOW()-INTERVAL '4 min')
ON CONFLICT (scan_id) DO NOTHING;

-- D5. Findings (6 findings, one per tool)
INSERT INTO findings (
    finding_id, scan_id, asset_id, tool, rule_id, title, severity,
    description, file_path, line_number, category,
    expected_annual_loss_inr, primary_loss_inr, secondary_loss_inr,
    loss_event_frequency, loss_magnitude_inr,
    verified, evidence, remediation
) VALUES
-- Tool 1: Semgrep (SAST — code security)
(
    'semgrep_hardcoded_jwt_secret_001',
    'scan_demo_sast_01', 'repo://fintech/payment-gateway',
    'semgrep', 'generic.secrets.jwt-hardcoded-secret',
    'Hardcoded JWT Signing Secret in Payment Handler', 'critical',
    'Cryptographic secret used to sign authorization tokens is hardcoded in source code. '
    'An attacker with repo read access can forge tokens for any user, bypassing all payment gateway access controls.',
    'src/auth/jwt_handler.py', 42, 'code',
    4550000.00, 2500000.00, 2050000.00, 0.70, 6500000.00, false,
    'JWT_SECRET = "super_secret_production_key_2026"  -- line 42',
    'Move secret to HashiCorp Vault or AWS Secrets Manager. Rotate immediately. Audit all tokens issued in past 30 days.'
),
-- Tool 2: Checkov (IaC — infrastructure security)
(
    'checkov_s3_bucket_public_002',
    'scan_demo_iac_02', 'iac://cloud/aws-production-vpc',
    'checkov', 'CKV_AWS_20',
    'S3 Bucket Has Public Read Access — Transaction Receipts Exposed', 'high',
    'S3 bucket storing customer transaction receipts has Block Public Access disabled. '
    'Any unauthenticated internet user can read all financial records — breaching DPDP Act and RBI-CSF.',
    'terraform/s3_storage.tf', 18, 'infrastructure',
    1820000.00, 820000.00, 1000000.00, 0.40, 4550000.00, true,
    'acl = "public-read"  -- terraform/s3_storage.tf line 18',
    'Set acl = "private". Add aws_s3_bucket_public_access_block with all block flags = true. Re-run Checkov to confirm.'
),
-- Tool 3: Cosign (supply-chain — container signing)
(
    'cosign_unsigned_container_003',
    'scan_demo_supply_03', 'image://registry.internal/checkout-api:v2.4',
    'cosign', 'COSIGN_SIGNATURE_MISSING',
    'Production Container Image Lacks Cryptographic Signature', 'high',
    'checkout-api:v2.4 deployed without a Sigstore cosign signature. '
    'No provenance chain exists — image could have been tampered post-build, enabling supply-chain compromise.',
    'registry.internal/checkout-api:v2.4', 1, 'supply-chain',
    1250000.00, 500000.00, 750000.00, 0.25, 5000000.00, false,
    'cosign verify registry.internal/checkout-api:v2.4 -> FAIL: no valid signatures found',
    'Add cosign sign --yes to GitHub Actions build workflow. Enforce Kyverno/OPA Gatekeeper to reject unsigned images.'
),
-- Tool 4: OWASP ZAP (DAST — web security)
(
    'zap_sqli_transfer_endpoint_004',
    'scan_demo_dast_04', 'url://api.fintech.internal/v1/transfer',
    'zap', '40018',
    'SQL Injection in Fund Transfer API — account_id Parameter', 'critical',
    'Blind time-based SQL injection confirmed in account_id parameter. '
    'Attacker can exfiltrate the full customer database and manipulate balances without authentication.',
    '/v1/transfer?account_id=1001', 1, 'web',
    5800000.00, 3000000.00, 2800000.00, 0.80, 7250000.00, false,
    'Payload: 1001 OR SLEEP(5)-- | Response time: 5.02 s (confirmed blind injection)',
    'Use parameterized queries (SQLAlchemy/Django ORM). Never concatenate user input into SQL. Add WAF rule to block SQLi.'
),
-- Tool 5: Falco (runtime detection)
(
    'falco_interactive_shell_005',
    'scan_demo_runtime_05', 'image://registry.internal/checkout-api:v2.4',
    'falco', 'Terminal shell in container',
    'Interactive Bash Shell Spawned in Production Container', 'critical',
    'Falco eBPF kernel probe detected unauthorized /bin/bash inside running checkout-api container. '
    'Strong indicator of active post-exploitation — attacker may be performing lateral movement or data exfiltration.',
    '/bin/bash', 102, 'runtime',
    3400000.00, 1400000.00, 2000000.00, 0.60, 5666666.00, false,
    'falco [2026-01-15T03:12:44Z]: Notice A shell was spawned in a container (user=root container=checkout-api)',
    'Enforce readOnlyRootFilesystem: true in pod spec. Drop CAP_SYS_ADMIN. Apply seccompProfile: RuntimeDefault.'
),
-- Tool 6: Suricata (network IDS)
(
    'suricata_c2_traffic_006',
    'scan_demo_net_06', 'url://api.fintech.internal/v1/transfer',
    'suricata', '2018959',
    'Outbound Cobalt Strike C2 Beaconing from Payment API Host', 'high',
    'Suricata IDS detected periodic HTTP beaconing from payment API host to a known Cobalt Strike team server. '
    'Beaconing interval (60 s) and user-agent match Cobalt Strike default malleable C2 profile signatures.',
    'pcap_stream:eth0', 504, 'network',
    2750000.00, 1250000.00, 1500000.00, 0.50, 5500000.00, true,
    'ET MALWARE Cobalt Strike Beaconing [SID:2018959] -> 45.142.212.100:443 every 60 s',
    'Isolate host via firewall ACL. Rotate all DB credentials and API keys. Open P1 incident. File RBI-CSITE report within 6 h.'
)
ON CONFLICT (finding_id) DO NOTHING;

-- D6. OPA Compliance Verdicts (18 verdicts across 5 regulations)
INSERT INTO compliance_verdicts (finding_id, regulation, control_id, control_name, status, rationale) VALUES
-- Hardcoded JWT secret
('semgrep_hardcoded_jwt_secret_001', 'RBI',      'RBI-CSF-SEC-4.1',   'Cryptographic Key Management',             'FAIL', 'Hardcoded signing key violates RBI CSF key-management mandate.'),
('semgrep_hardcoded_jwt_secret_001', 'ISO27001',  'A.8.24',            'Use of Cryptography',                      'FAIL', 'Secret in unencrypted source code violates ISO 27001 A.8.24.'),
('semgrep_hardcoded_jwt_secret_001', 'DPDP',     'DPDP-ACT-SEC-8',    'Reasonable Security Safeguards',            'FAIL', 'Failure to safeguard customer auth tokens violates DPDP Act S.8.'),
('semgrep_hardcoded_jwt_secret_001', 'CERT_IN',  'CERT-IN-DIR-2022',  'Credential Security and Reporting',         'FAIL', 'Compromised credential must be reported to CERT-In within 6 hours.'),
-- Public S3 bucket
('checkov_s3_bucket_public_002',     'SEBI',     'SEBI-CSCRF-S3.2',   'Cloud Data Protection and Access Control',  'FAIL', 'Publicly readable financial records violate SEBI CSCRF cloud baseline.'),
('checkov_s3_bucket_public_002',     'RBI',      'RBI-CSF-CLD-3',     'Cloud Access Control Baseline',             'FAIL', 'Financial storage must block public access per RBI Cloud Framework.'),
('checkov_s3_bucket_public_002',     'ISO27001',  'A.8.12',            'Data Leakage Prevention',                   'FAIL', 'Public bucket constitutes preventable data leakage under ISO 27001 A.8.12.'),
('checkov_s3_bucket_public_002',     'DPDP',     'DPDP-ACT-DATA-4',   'Purpose Limitation and Data Security',      'FAIL', 'Customer PII in public storage violates DPDP Act data protection obligations.'),
-- SQL injection
('zap_sqli_transfer_endpoint_004',   'NIST_CSF', 'PR.DS-1',           'Data Protection and Application Security',  'FAIL', 'SQLi enables unauthorized data manipulation — NIST PR.DS-1 failure.'),
('zap_sqli_transfer_endpoint_004',   'RBI',      'RBI-CSF-APP-2',     'Application Vulnerability Assessment',      'FAIL', 'OWASP Top-10 A03 injection in production payment API violates RBI AppSec mandate.'),
('zap_sqli_transfer_endpoint_004',   'SEBI',     'SEBI-CSCRF-APP-1',  'API Security Standards',                    'FAIL', 'Critical API injection enabling arbitrary DB reads violates SEBI API security.'),
-- Unsigned container
('cosign_unsigned_container_003',    'ISO27001',  'A.8.30',            'Outsourced Development and Supply Chain',   'FAIL', 'No signature verification — ISO 27001 A.8.30 supply chain control failure.'),
('cosign_unsigned_container_003',    'NIST_CSF', 'ID.SC-4',           'Supply Chain Risk Management',              'FAIL', 'No CI/CD signature check violates NIST CSF supply chain monitoring requirement.'),
-- Interactive shell in container
('falco_interactive_shell_005',      'NIST_CSF', 'DE.CM-1',           'Network and Host Continuous Monitoring',    'FAIL', 'Unauthorized shell in production container indicates active breach (NIST DE.CM-1).'),
('falco_interactive_shell_005',      'RBI',      'RBI-CSF-SOC-3',     'Security Operations and Incident Response', 'FAIL', 'Active intrusion signal must trigger immediate RBI incident response process.'),
-- Cobalt Strike C2
('suricata_c2_traffic_006',          'RBI',      'RBI-CSF-SOC-5',     'Cyber Threat Intelligence and IR',          'FAIL', 'Active C2 beaconing requires mandatory RBI CSITE notification within 6 hours.'),
('suricata_c2_traffic_006',          'CERT_IN',  'CERT-IN-DIR-2022',  'Cyber Incident Reporting',                  'FAIL', 'Cobalt Strike is a notifiable incident under CERT-In 2022 directive (6-hour SLA).'),
('suricata_c2_traffic_006',          'NIST_CSF', 'RS.CO-2',           'Incident Response Communications',          'FAIL', 'Threat actor C2 comms must be reported per NIST RS.CO-2 requirement.')
ON CONFLICT DO NOTHING;

-- D7. Kafka Events (what graph-service consumed to create findings above)
INSERT INTO kafka_events (topic, partition_num, kafka_offset, key, payload, producer, processed) VALUES
('findings.raw', 0, 1001, 'semgrep_hardcoded_jwt_secret_001',
 '{"finding_id":"semgrep_hardcoded_jwt_secret_001","tool":"semgrep","severity":"critical","asset_id":"repo://fintech/payment-gateway","expected_annual_loss_inr":4550000}',
 'code-security-svc', true),
('findings.raw', 0, 1002, 'checkov_s3_bucket_public_002',
 '{"finding_id":"checkov_s3_bucket_public_002","tool":"checkov","severity":"high","asset_id":"iac://cloud/aws-production-vpc","expected_annual_loss_inr":1820000}',
 'code-security-svc', true),
('findings.raw', 1, 2001, 'cosign_unsigned_container_003',
 '{"finding_id":"cosign_unsigned_container_003","tool":"cosign","severity":"high","asset_id":"image://registry.internal/checkout-api:v2.4","expected_annual_loss_inr":1250000}',
 'supply-chain-svc', true),
('findings.raw', 2, 3001, 'zap_sqli_transfer_endpoint_004',
 '{"finding_id":"zap_sqli_transfer_endpoint_004","tool":"zap","severity":"critical","asset_id":"url://api.fintech.internal/v1/transfer","expected_annual_loss_inr":5800000}',
 'web-security-svc', true),
('findings.raw', 1, 2002, 'falco_interactive_shell_005',
 '{"finding_id":"falco_interactive_shell_005","tool":"falco","severity":"critical","asset_id":"image://registry.internal/checkout-api:v2.4","expected_annual_loss_inr":3400000}',
 'runtime-monitor-svc', true),
('findings.raw', 2, 3002, 'suricata_c2_traffic_006',
 '{"finding_id":"suricata_c2_traffic_006","tool":"suricata","severity":"high","asset_id":"url://api.fintech.internal/v1/transfer","expected_annual_loss_inr":2750000}',
 'network-monitor-svc', true)
ON CONFLICT DO NOTHING;


-- ═════════════════════════════════════════════════════════════════════════════
-- SECTION E  Verification
-- Expected counts: assets=4, workflow_runs=1, agent_tool_decisions=6,
--                 scans=6, findings=6, compliance_verdicts=18, kafka_events=6
-- ═════════════════════════════════════════════════════════════════════════════

SELECT 'assets'              AS table_name, count(*) AS rows FROM assets
UNION ALL SELECT 'workflow_runs',        count(*) FROM workflow_runs
UNION ALL SELECT 'agent_tool_decisions', count(*) FROM agent_tool_decisions
UNION ALL SELECT 'scans',               count(*) FROM scans
UNION ALL SELECT 'findings',            count(*) FROM findings
UNION ALL SELECT 'compliance_verdicts', count(*) FROM compliance_verdicts
UNION ALL SELECT 'kafka_events',        count(*) FROM kafka_events
ORDER BY table_name;

-- Risk Queue (top findings by INR annual exposure):
-- SELECT finding_id, tool, severity, expected_annual_loss_inr
-- FROM findings ORDER BY expected_annual_loss_inr DESC;

-- Compliance summary by regulation:
-- SELECT regulation, status, count(*) AS controls
-- FROM compliance_verdicts GROUP BY regulation, status ORDER BY regulation;

-- AI agent tool selection trace for demo workflow:
-- SELECT tool, decision, reason FROM agent_tool_decisions WHERE workflow_id = 'wf_demo_001';
