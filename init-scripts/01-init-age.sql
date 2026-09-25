-- SecuriX Knowledge Graph Initialization Script
-- PostgreSQL + Apache AGE (Apache Graph Extension)

-- 1. Enable Apache AGE extension
CREATE EXTENSION IF NOT EXISTS age;
LOAD 'age';
SET search_path = ag_catalog, "$user", public;

-- 2. Create the SecuriX Security Graph
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM ag_graph WHERE name = 'securix') THEN
        PERFORM create_graph('securix');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM ag_graph WHERE name = 'securix_graph') THEN
        PERFORM create_graph('securix_graph');
    END IF;
END $$;

-- 2b. Reset search_path so all app tables are created in public schema
RESET search_path;

-- 3. Relational Materialized Tables for Hybrid High-Speed Querying & Indexing
-- Section 3.4 of SecuriX Implementation Guide
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

CREATE TABLE IF NOT EXISTS assets (
    asset_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(64) NOT NULL, -- repo, container_image, iac_source, web_endpoint, host
    criticality VARCHAR(32) DEFAULT 'HIGH', -- CRITICAL, HIGH, MEDIUM, LOW
    owner VARCHAR(128) DEFAULT 'SecOps',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR(255) PRIMARY KEY,
    scan_id VARCHAR(128) NOT NULL,
    asset_id VARCHAR(255) REFERENCES assets(asset_id) ON DELETE CASCADE,
    tool VARCHAR(64) NOT NULL,
    rule_id VARCHAR(255),
    title VARCHAR(512) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    description TEXT,
    file_path TEXT,
    line_number INT,
    category VARCHAR(64) DEFAULT 'vulnerability',
    expected_annual_loss_inr NUMERIC(15, 2) DEFAULT 0.0,
    primary_loss_inr NUMERIC(15, 2) DEFAULT 0.0,
    secondary_loss_inr NUMERIC(15, 2) DEFAULT 0.0,
    loss_event_frequency NUMERIC(6, 4) DEFAULT 0.1,
    loss_magnitude_inr NUMERIC(15, 2) DEFAULT 500000.0,
    verified BOOLEAN DEFAULT FALSE,
    verified_by VARCHAR(128),
    verified_at TIMESTAMP WITH TIME ZONE,
    raw_output JSONB DEFAULT '{}',
    evidence TEXT,
    remediation TEXT,
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS compliance_verdicts (
    id SERIAL PRIMARY KEY,
    finding_id VARCHAR(255) REFERENCES findings(finding_id) ON DELETE CASCADE,
    regulation VARCHAR(64) NOT NULL, -- RBI, SEBI, ISO27001, NIST_CSF, DPDP
    control_id VARCHAR(128) NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL, -- PASS | FAIL | NOT_APPLICABLE
    rationale TEXT,
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id VARCHAR(128) PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    tool VARCHAR(64) NOT NULL,
    status VARCHAR(32) DEFAULT 'COMPLETED',
    findings_count INT DEFAULT 0,
    total_exposure_inr NUMERIC(15, 2) DEFAULT 0.0,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Create Indexes for Real-Time Query Performance
CREATE INDEX IF NOT EXISTS idx_findings_exposure ON findings(expected_annual_loss_inr DESC);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_compliance_reg ON compliance_verdicts(regulation, status);
CREATE INDEX IF NOT EXISTS idx_risk_queue_tenant ON risk_queue(tenant_id, rank);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_repo ON scan_jobs(repo_id, status);

-- 5. Seed Pre-Populated Realistic Demo Assets & Findings
INSERT INTO assets (asset_id, name, asset_type, criticality, owner) VALUES
('repo://fintech/payment-gateway', 'Payment Gateway Core', 'repo', 'CRITICAL', 'Payments Team'),
('image://registry.internal/checkout-api:v2.4', 'Checkout API Container', 'container_image', 'CRITICAL', 'Core Banking Team'),
('iac://cloud/aws-production-vpc', 'AWS Production VPC Terraform', 'iac_source', 'HIGH', 'Cloud Platform Team'),
('url://api.fintech.internal/v1/transfer', 'Fund Transfer API Endpoint', 'web_endpoint', 'CRITICAL', 'API Security')
ON CONFLICT (asset_id) DO NOTHING;

INSERT INTO findings (
    finding_id, scan_id, asset_id, tool, rule_id, title, severity,
    description, file_path, line_number, category,
    expected_annual_loss_inr, primary_loss_inr, secondary_loss_inr,
    loss_event_frequency, loss_magnitude_inr, verified, evidence, remediation
) VALUES
(
    'semgrep_hardcoded_jwt_secret_001',
    'scan_demo_sast_01',
    'repo://fintech/payment-gateway',
    'semgrep',
    'generic.secrets.jwt-hardcoded-secret',
    'Hardcoded JWT Signing Secret in Payment Handler',
    'critical',
    'Cryptographic secret key used to sign authorization tokens is hardcoded in source repository.',
    'src/auth/jwt_handler.py',
    42,
    'code',
    4550000.00,
    2500000.00,
    2050000.00,
    0.70,
    6500000.00,
    false,
    'JWT_SECRET = "super_secret_production_key_2026"',
    'Move secrets to HashiCorp Vault or AWS Secrets Manager. Do not store secrets in source code.'
),
(
    'checkov_s3_bucket_public_002',
    'scan_demo_iac_02',
    'iac://cloud/aws-production-vpc',
    'checkov',
    'CKV_AWS_20',
    'S3 Bucket has Public Read Access Enabled',
    'high',
    'S3 bucket storing transaction receipts does not have Block Public Access enabled, risking mass customer PII leak.',
    'terraform/s3_storage.tf',
    18,
    'infrastructure',
    1820000.00,
    820000.00,
    1000000.00,
    0.40,
    4550000.00,
    true,
    'acl = "public-read"',
    'Set acl = "private" and enable aws_s3_bucket_public_access_block.'
),
(
    'cosign_unsigned_container_003',
    'scan_demo_supply_03',
    'image://registry.internal/checkout-api:v2.4',
    'cosign',
    'COSIGN_SIGNATURE_MISSING',
    'Production Container Image Lacks Valid Cryptographic Signature',
    'high',
    'Container image was deployed without Sigstore cosign keyless cryptographic signature verification.',
    'registry.internal/checkout-api:v2.4',
    1,
    'supply-chain',
    1250000.00,
    500000.00,
    750000.00,
    0.25,
    5000000.00,
    false,
    'cosign verify failed: no valid signatures found in registry',
    'Configure CI pipeline with cosign sign --yes in GitHub Actions.'
),
(
    'zap_sqli_transfer_endpoint_004',
    'scan_demo_dast_04',
    'url://api.fintech.internal/v1/transfer',
    'zap',
    '40018',
    'SQL Injection Vulnerability in Account Balance Lookup',
    'critical',
    'Unescaped parameter account_id allows blind time-based SQL injection on internal database.',
    '/v1/transfer?account_id=1001',
    1,
    'web',
    5800000.00,
    3000000.00,
    2800000.00,
    0.80,
    7250000.00,
    false,
    'Parameter account_id vulnerable with payload 1001 OR 1=1',
    'Use parameterized queries or ORM binding. Never concatenate user input into SQL strings.'
),
(
    'falco_interactive_shell_005',
    'scan_demo_runtime_05',
    'image://registry.internal/checkout-api:v2.4',
    'falco',
    'Terminal shell in container',
    'Interactive Bash Shell Spawned Inside Production Container',
    'critical',
    'Falco kernel probe detected unauthorized interactive /bin/bash shell execution in running container.',
    '/bin/bash',
    102,
    'runtime',
    3400000.00,
    1400000.00,
    2000000.00,
    0.60,
    5666666.00,
    false,
    'falco alert: Notice A shell was spawned in a container with an attached terminal',
    'Enforce read-only root filesystems and drop CAP_SYS_ADMIN capabilities.'
),
(
    'suricata_c2_traffic_006',
    'scan_demo_net_06',
    'url://api.fintech.internal/v1/transfer',
    'suricata',
    '2018959',
    'Outbound Cobalt Strike C2 Beaconing Detected',
    'high',
    'Suricata network engine detected regular HTTP beaconing matching known threat actor infrastructure.',
    'pcap_stream:eth0',
    504,
    'network',
    2750000.00,
    1250000.00,
    1500000.00,
    0.50,
    5500000.00,
    true,
    'ET MALWARE Cobalt Strike Beaconing User-Agent observed on port 443',
    'Isolate the compromised host immediately and rotate all database credentials.'
)
ON CONFLICT (finding_id) DO NOTHING;

-- Seed OPA Compliance Verdicts for regulations
INSERT INTO compliance_verdicts (finding_id, regulation, control_id, control_name, status, rationale) VALUES
('semgrep_hardcoded_jwt_secret_001', 'RBI', 'RBI-CSF-SEC-4.1', 'Cryptographic Key Management', 'FAIL', 'Hardcoded credentials violate RBI key management mandate.'),
('semgrep_hardcoded_jwt_secret_001', 'ISO27001', 'A.8.24', 'Use of Cryptography', 'FAIL', 'Secret keys must not be stored in unencrypted repository code.'),
('semgrep_hardcoded_jwt_secret_001', 'DPDP', 'DPDP-ACT-SEC-8', 'Reasonable Security Safeguards', 'FAIL', 'Failure to safeguard personal customer authentication tokens.'),
('checkov_s3_bucket_public_002', 'SEBI', 'SEBI-CSCRF-S3.2', 'Cloud Data Protection & Access Control', 'FAIL', 'Public cloud storage violates SEBI financial data segregation.'),
('checkov_s3_bucket_public_002', 'RBI', 'RBI-CSF-CLD-3', 'Cloud Access Control Baseline', 'FAIL', 'Storage containing financial records must restrict public access.'),
('checkov_s3_bucket_public_002', 'ISO27001', 'A.8.12', 'Data Leakage Prevention', 'FAIL', 'Public bucket exposure constitutes preventable data leakage risk.'),
('zap_sqli_transfer_endpoint_004', 'NIST_CSF', 'PR.DS-1', 'Data-at-Rest and Application Protection', 'FAIL', 'Critical SQL injection permits unauthorized data manipulation.'),
('zap_sqli_transfer_endpoint_004', 'RBI', 'RBI-CSF-APP-2', 'Application Vulnerability Assessment', 'FAIL', 'OWASP Top 10 A03 Injection flaw found in production endpoint.'),
('zap_sqli_transfer_endpoint_004', 'SEBI', 'SEBI-CSCRF-APP-1', 'API Security Standards', 'FAIL', 'Critical API vulnerability enables arbitrary database reads.'),
('cosign_unsigned_container_003', 'ISO27001', 'A.8.30', 'Outsourced Development & Supply Chain', 'FAIL', 'Unsigned image cannot be verified for provenance and integrity.'),
('falco_interactive_shell_005', 'NIST_CSF', 'DE.CM-1', 'Network & Host Continuous Monitoring', 'FAIL', 'Unauthorized shell execution detected during container runtime.'),
('suricata_c2_traffic_006', 'RBI', 'RBI-CSF-SOC-5', 'Cyber Threat Intelligence & Incident Response', 'FAIL', 'Active C2 communication detected requiring immediate containment.')
ON CONFLICT DO NOTHING;
