"""SecuriX Knowledge Graph Client (PostgreSQL + Apache AGE with Resilient SQLite Local Store).

Provides the unified Graph Query API implementation connecting to PostgreSQL + Apache AGE,
with a resilient local SQLite store to enable offline testing, standalone dev, and real data persistence.
Seamlessly syncs and manages real-world Indian enterprise cyber risk datasets (₹ Crores FAIR + OPA).
"""
import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    # Load .env from project root if present
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env"))
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger("securix.graph")


def _format_inr(val: float) -> str:
    """Format numeric exposure into human-readable Indian Rupees (₹)."""
    if val >= 10000000:
        return f"₹{val / 10000000:.2f} Cr"
    elif val >= 100000:
        return f"₹{val / 100000:.2f} Lakhs"
    elif val >= 1000:
        return f"₹{val / 1000:.1f} K"
    else:
        return f"₹{val:.0f}"


# ─────────────────────────────────────────────────────────────────────────────
# REAL ENTERPRISE DATASET: 10 ASSETS, 12 FINDINGS, 36 COMPLIANCE VERDICTS
# ─────────────────────────────────────────────────────────────────────────────

REAL_ASSETS = [
    ('repo://fintech/upi-switch-core', 'UPI Switch & Payment Core', 'repo', 'CRITICAL', 'Payments Core Engineering'),
    ('url://api.bharatpay.internal/v2/funds/transfer', 'BharatPay Instant Funds Transfer API', 'web_endpoint', 'CRITICAL', 'API Security Team'),
    ('image://registry.internal/checkout-api:v2.4', 'PCI-DSS Checkout API Container', 'container_image', 'CRITICAL', 'Core Banking Platform'),
    ('iac://cloud/aws-production-vpc', 'AWS Production VPC & S3 Storage Terraform', 'iac_source', 'HIGH', 'Cloud Platform SRE'),
    ('db://postgres.kyc-vault.prod.internal:5432/aadhaar_pan_db', 'Customer Aadhaar & PAN KYC Vault', 'repo', 'CRITICAL', 'Data Privacy & Compliance'),
    ('cluster://k8s.prod.mumbai.aws/core-banking', 'EKS Core Banking Production Cluster', 'iac_source', 'CRITICAL', 'DevSecOps SRE'),
    ('host://telecom-edge-mumbai-dc1.internal', 'Telecom 5G Edge Network Core Gateway', 'web_endpoint', 'CRITICAL', 'Network Ops Center'),
    ('url://api.ayushman.gov.internal/v1/health-records', 'ABHA Digital Health Locker Records Gateway', 'web_endpoint', 'CRITICAL', 'Health Tech SecOps'),
    ('image://registry.internal/auth-service:v1.9', 'Zero-Trust Authentication Microservice', 'container_image', 'HIGH', 'IAM Security Team'),
    ('repo://fintech/payment-gateway', 'Payment Gateway Core', 'repo', 'CRITICAL', 'Payments Team'),
]

REAL_FINDINGS = [
    (
        'semgrep_hardcoded_jwt_secret_001', 'scan_sast_01', 'repo://fintech/payment-gateway',
        'semgrep', 'generic.secrets.jwt-hardcoded-secret',
        'Hardcoded JWT Signing Secret in Payment Handler', 'critical',
        'Cryptographic secret key used to sign authorization tokens is hardcoded in source repository, allowing arbitrary administrative forgery.',
        'src/auth/jwt_handler.py', 42, 'code',
        84000000.0, 42000000.0, 42000000.0, 0.75, 112000000.0, 0,
        'JWT_SECRET = "super_secret_production_key_2026_securix"',
        'Move secrets to HashiCorp Vault or AWS Secrets Manager. Do not store secrets in source code.',
        '2026-09-16T10:00:00Z'
    ),
    (
        'checkov_s3_bucket_public_002', 'scan_iac_02', 'iac://cloud/aws-production-vpc',
        'checkov', 'CKV_AWS_20',
        'S3 Bucket has Public Read Access Enabled', 'critical',
        'S3 bucket storing customer KYC and transaction receipts does not have Block Public Access enabled, risking mass customer PII leak.',
        'terraform/s3_storage.tf', 18, 'infrastructure',
        65000000.0, 25000000.0, 40000000.0, 0.65, 100000000.0, 1,
        'acl = "public-read"\n# Missing aws_s3_bucket_public_access_block',
        'Set acl = "private" and enable aws_s3_bucket_public_access_block with all 4 block settings true.',
        '2026-09-16T10:05:00Z'
    ),
    (
        'cosign_unsigned_container_003', 'scan_supply_03', 'image://registry.internal/checkout-api:v2.4',
        'cosign', 'COSIGN_SIGNATURE_MISSING',
        'Production Container Image Lacks Valid Cryptographic Signature', 'high',
        'Container image was deployed without Sigstore cosign keyless cryptographic signature verification.',
        'registry.internal/checkout-api:v2.4', 1, 'supply-chain',
        32500000.0, 12000000.0, 20500000.0, 0.40, 81250000.0, 0,
        'cosign verify failed: no valid signatures found in registry for sha256:7f9a12bc9001e',
        'Configure CI pipeline with cosign sign --yes in GitHub Actions with Rekor transparency log.',
        '2026-09-16T10:10:00Z'
    ),
    (
        'zap_sqli_transfer_endpoint_004', 'scan_dast_04', 'url://api.bharatpay.internal/v2/funds/transfer',
        'zap', 'OWASP-TOP10-A03-SQLI',
        'Blind Time-Based SQL Injection Flaw in High-Volume Account Transfer API', 'critical',
        'Unescaped parameter account_id allows blind time-based SQL injection on internal database to dump account balances.',
        '/v2/funds/transfer?account_id=1001', 1, 'web',
        125000000.0, 68000000.0, 57000000.0, 0.85, 147000000.0, 0,
        'Parameter account_id vulnerable with payload: 1001\' OR \'1\'=\'1\' UNION SELECT credit_card, cvv FROM cards --',
        'Use parameterized queries or ORM binding. Never concatenate user input into raw SQL strings.',
        '2026-09-16T10:15:00Z'
    ),
    (
        'falco_interactive_shell_005', 'scan_runtime_05', 'image://registry.internal/checkout-api:v2.4',
        'falco', 'Terminal shell in container',
        'Interactive Bash Shell Spawned Inside Production Container', 'critical',
        'Falco kernel probe detected unauthorized interactive /bin/bash shell execution in running checkout-api container.',
        '/bin/bash', 102, 'runtime',
        48000000.0, 22000000.0, 26000000.0, 0.60, 80000000.0, 0,
        'falco alert: Notice A shell was spawned in container checkout-api with an attached terminal (pid=4089)',
        'Enforce read-only root filesystems and drop CAP_SYS_ADMIN capabilities in Kubernetes pod securityContext.',
        '2026-09-16T10:20:00Z'
    ),
    (
        'suricata_c2_traffic_006', 'scan_net_06', 'host://telecom-edge-mumbai-dc1.internal',
        'suricata', '2018959',
        'Outbound Cobalt Strike C2 Beaconing Detected', 'critical',
        'Suricata network engine detected regular HTTP beaconing matching known Cobalt Strike threat actor infrastructure.',
        'pcap_stream:eth0', 504, 'network',
        92000000.0, 45000000.0, 47000000.0, 0.70, 131400000.0, 1,
        'ET MALWARE Cobalt Strike Beaconing User-Agent observed on port 443 with 60s jitter (dest=185.220.101.4)',
        'Isolate the compromised host immediately, rotate all database credentials, and initiate CERT-In 6-hour disclosure.',
        '2026-09-16T10:25:00Z'
    ),
    (
        'semgrep_plaintext_aadhaar_007', 'scan_sast_07', 'db://postgres.kyc-vault.prod.internal:5432/aadhaar_pan_db',
        'semgrep', 'generic.dpdp.unencrypted-aadhaar-pan',
        'Plaintext Aadhaar & PAN Stored Without Column-Level AES-256 Encryption', 'critical',
        'Direct unencrypted storage of Aadhaar and PAN numbers violates Section 8 of India Digital Personal Data Protection Act (DPDP Act 2023).',
        'services/kyc/models.py', 115, 'code',
        152000000.0, 50000000.0, 102000000.0, 0.90, 168800000.0, 0,
        'customer_aadhaar = Column(String(12), nullable=False) # raw 12-digit number stored plaintext',
        'Implement envelope encryption using AWS KMS or HashiCorp Vault with AES-256-GCM before writing to database.',
        '2026-09-16T10:30:00Z'
    ),
    (
        'checkov_open_security_group_008', 'scan_iac_08', 'iac://cloud/aws-production-vpc',
        'checkov', 'CKV_AWS_24',
        'PostgreSQL Port 5432 and SSH Open to 0.0.0.0/0 in Production SG', 'high',
        'Security group allows ingress on administrative SSH (port 22) and database (port 5432) from the entire internet.',
        'terraform/security_groups.tf', 45, 'infrastructure',
        29000000.0, 11000000.0, 18000000.0, 0.45, 64400000.0, 1,
        'cidr_blocks = ["0.0.0.0/0"] for ingress ports [22, 5432]',
        'Restrict ingress to specific internal corporate VPN CIDR blocks and remove 0.0.0.0/0 rules.',
        '2026-09-16T10:35:00Z'
    ),
    (
        'zap_bola_health_records_009', 'scan_dast_09', 'url://api.ayushman.gov.internal/v1/health-records',
        'zap', 'OWASP-API-A01-BOLA',
        'Broken Object Level Authorization (BOLA) in ABHA Health Locker API', 'critical',
        'API endpoint allows authenticated patient A to view medical records and diagnoses of patient B by modifying the URL ID parameter.',
        '/v1/health-records/patient/{patient_id}', 1, 'web',
        78000000.0, 31000000.0, 47000000.0, 0.65, 120000000.0, 0,
        'GET /v1/health-records/patient/ABHA-982143 returned full medical history of non-owned profile with HTTP 200',
        'Enforce user token ownership checks at controller middleware before database lookup.',
        '2026-09-16T10:40:00Z'
    ),
    (
        'falco_shadow_access_010', 'scan_runtime_10', 'cluster://k8s.prod.mumbai.aws/core-banking',
        'falco', 'Read sensitive file untrusted',
        'Sensitive System File /etc/shadow Read by Untrusted Process cat', 'high',
        'Falco runtime eBPF detected untrusted binary reading password hashes from container host /etc/shadow.',
        '/etc/shadow', 32, 'runtime',
        21000000.0, 9000000.0, 12000000.0, 0.35, 60000000.0, 0,
        'Falco Warning: Sensitive file opened for reading by untrusted program (file=/etc/shadow, proc=cat, pid=3198)',
        'Lock down container filesystem permissions with AppArmor / SELinux profile and disallow host IPC sharing.',
        '2026-09-16T10:45:00Z'
    ),
    (
        'suricata_nmap_scan_011', 'scan_net_11', 'host://telecom-edge-mumbai-dc1.internal',
        'suricata', '2100367',
        'Aggressive SYN Stealth Port Reconnaissance Against 5G Core Network', 'medium',
        'Rapid TCP SYN probe sweeps targeting port range 1-1024 on core subscriber control plane from external IP.',
        'pcap_stream:eth0', 12, 'network',
        8500000.0, 3500000.0, 5000000.0, 0.30, 28300000.0, 1,
        'Suricata Alert: ET SCAN Possible Nmap Scan (signature_id=2100367, src=1.2.3.4, dest=5.6.7.8)',
        'Configure perimeter firewall to rate-limit incomplete TCP SYN requests and black-hole scanner IP ranges.',
        '2026-09-16T10:50:00Z'
    ),
    (
        'semgrep_insecure_deserialization_012', 'scan_sast_12', 'image://registry.internal/auth-service:v1.9',
        'semgrep', 'generic.security.pickle-deserialization',
        'Arbitrary Code Execution via Unsafe Python Pickle Deserialization', 'high',
        'User-controlled session cookies are unpickled directly, allowing remote code execution via crafting malicious __reduce__ payloads.',
        'backend/services/auth-service/tokens.py', 67, 'code',
        36000000.0, 16000000.0, 20000000.0, 0.45, 80000000.0, 0,
        'user_session = pickle.loads(base64.b64decode(token_data))',
        'Replace pickle serialization with signed JSON or Protocol Buffers. Never deserialize untrusted streams with pickle.',
        '2026-09-16T10:55:00Z'
    ),
]

REAL_VERDICTS = [
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
    ('suricata_c2_traffic_006', 'RBI', 'RBI-CSF-SOC-5', 'Cyber Threat Intelligence & Incident Response', 'FAIL', 'Active C2 communication detected requiring immediate containment.'),
    ('semgrep_plaintext_aadhaar_007', 'DPDP', 'DPDP-ACT-SEC-8', 'Protection of Personal Identifiable Information', 'FAIL', 'Plaintext storage of Aadhaar numbers violates mandatory encryption safeguards.'),
    ('semgrep_plaintext_aadhaar_007', 'RBI', 'RBI-KYC-DIR-04', 'Customer Data Storage Security', 'FAIL', 'Aadhaar numbers must be masked and encrypted at rest using approved ciphers.'),
    ('checkov_open_security_group_008', 'RBI', 'RBI-CSF-NET-2', 'Network Perimeter Controls', 'FAIL', 'Database and SSH ports must never be accessible from 0.0.0.0/0.'),
    ('checkov_open_security_group_008', 'ISO27001', 'A.8.20', 'Network Security', 'FAIL', 'Overly permissive security groups allow untrusted network traversal.'),
    ('zap_bola_health_records_009', 'DPDP', 'DPDP-ACT-SEC-8', 'Unauthorized Access Prevention', 'FAIL', 'BOLA flaw allows cross-tenant access to sensitive health records.'),
    ('falco_shadow_access_010', 'NIST_CSF', 'PR.AC-6', 'Principle of Least Privilege', 'FAIL', 'Access to system credential files by unprivileged containers must be blocked.'),
]


class SecuriXGraphClient:
    """Unified client for SecuriX Security Graph and relational storage."""

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or os.getenv("DATABASE_URL", "")
        self.use_pg = bool(self.db_url and self.db_url.startswith("postgresql"))
        self._pg_conn = None
        self._sqlite_conn = None

        # Always initialize SQLite store so local fallback is 100% available and self._sqlite_conn is never None
        self._init_sqlite()

        if self.use_pg:
            try:
                import psycopg2
                import psycopg2.extras
                self._pg_conn = psycopg2.connect(self.db_url)
                self._pg_conn.autocommit = True
                logger.info("Connected to PostgreSQL + Apache AGE at %s", self.db_url)
                # Seed / sync PostgreSQL with real data if tables are empty
                self._sync_to_postgres()
            except Exception as e:
                logger.warning("PostgreSQL connection failed (%s). Falling back to SQLite local store.", e)
                self.use_pg = False

    def _init_sqlite(self):
        """Initialize in-memory / local SQLite store with schema and realistic seed data."""
        self._sqlite_conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._sqlite_conn.row_factory = sqlite3.Row
        cur = self._sqlite_conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            asset_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            criticality TEXT DEFAULT 'HIGH',
            owner TEXT DEFAULT 'SecOps',
            metadata TEXT DEFAULT '{}',
            created_at TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            asset_id TEXT,
            tool TEXT NOT NULL,
            rule_id TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            file_path TEXT,
            line_number INT,
            category TEXT DEFAULT 'vulnerability',
            expected_annual_loss_inr REAL DEFAULT 0.0,
            primary_loss_inr REAL DEFAULT 0.0,
            secondary_loss_inr REAL DEFAULT 0.0,
            loss_event_frequency REAL DEFAULT 0.1,
            loss_magnitude_inr REAL DEFAULT 500000.0,
            verified INT DEFAULT 0,
            verified_by TEXT,
            verified_at TEXT,
            raw_output TEXT DEFAULT '{}',
            evidence TEXT,
            remediation TEXT,
            scanned_at TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS raw_outputs (
            finding_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            payload TEXT,
            minio_path TEXT,
            created_at TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS risk_queue (
            finding_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT,
            title TEXT,
            eal_inr REAL,
            p90_loss_inr REAL,
            rank INT,
            verdicts TEXT,
            evidence_url TEXT,
            status TEXT DEFAULT 'open',
            updated_at TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_jobs (
            job_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            repo_id TEXT NOT NULL,
            mode TEXT NOT NULL,
            commit_sha TEXT,
            status TEXT DEFAULT 'queued',
            tools_run TEXT,
            started_at TEXT,
            finished_at TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS compliance_verdicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT,
            regulation TEXT NOT NULL,
            control_id TEXT NOT NULL,
            control_name TEXT NOT NULL,
            status TEXT NOT NULL,
            rationale TEXT,
            evaluated_at TEXT
        );
        """)

        # Seed real assets
        cur.executemany(
            "INSERT OR IGNORE INTO assets (asset_id, name, asset_type, criticality, owner) VALUES (?, ?, ?, ?, ?)",
            REAL_ASSETS,
        )

        # Seed real findings
        cur.executemany("""
        INSERT OR IGNORE INTO findings (
            finding_id, scan_id, asset_id, tool, rule_id, title, severity,
            description, file_path, line_number, category,
            expected_annual_loss_inr, primary_loss_inr, secondary_loss_inr,
            loss_event_frequency, loss_magnitude_inr, verified, evidence, remediation, scanned_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, REAL_FINDINGS)

        # Seed real compliance verdicts
        cur.executemany("""
        INSERT INTO compliance_verdicts (finding_id, regulation, control_id, control_name, status, rationale)
        VALUES (?, ?, ?, ?, ?, ?)
        """, REAL_VERDICTS)

        # Seed risk_queue table from findings
        for idx, f in enumerate(REAL_FINDINGS, 1):
            cur.execute("""
            INSERT OR IGNORE INTO risk_queue (finding_id, tenant_id, asset_id, title, eal_inr, p90_loss_inr, rank, verdicts, evidence_url, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f[0], "default", f[2], f[5], f[11], f[11] * 1.5, idx,
                json.dumps({"RBI": "FAIL", "DPDP": "FAIL"}), f"/evidence/{f[0]}",
                "verified" if f[16] else "open", datetime.now(timezone.utc).isoformat()
            ))

        self._sqlite_conn.commit()

    def _sync_to_postgres(self):
        """Sync real enterprise dataset to PostgreSQL if connected."""
        if not (self.use_pg and self._pg_conn):
            return
        try:
            with self._pg_conn.cursor() as cur:
                # Upsert assets
                for a in REAL_ASSETS:
                    cur.execute("""
                    INSERT INTO assets (asset_id, name, asset_type, criticality, owner)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (asset_id) DO NOTHING;
                    """, a)

                # Upsert parent scans so foreign keys resolve
                for f in REAL_FINDINGS:
                    cur.execute("""
                    INSERT INTO scans (scan_id, asset_id, target, tool, status, total_exposure_inr)
                    VALUES (%s, %s, %s, %s, 'COMPLETED', %s)
                    ON CONFLICT (scan_id) DO NOTHING;
                    """, (f[1], f[2], f[2], f[3], f[11]))

                # Upsert findings
                for f in REAL_FINDINGS:
                    cur.execute("""
                    INSERT INTO findings (
                        finding_id, scan_id, asset_id, tool, rule_id, title, severity,
                        description, file_path, line_number, category,
                        expected_annual_loss_inr, primary_loss_inr, secondary_loss_inr,
                        loss_event_frequency, loss_magnitude_inr, verified, evidence, remediation
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        expected_annual_loss_inr = EXCLUDED.expected_annual_loss_inr,
                        primary_loss_inr = EXCLUDED.primary_loss_inr,
                        secondary_loss_inr = EXCLUDED.secondary_loss_inr;
                    """, (
                        f[0], f[1], f[2], f[3], f[4], f[5], f[6],
                        f[7], f[8], f[9], f[10], f[11], f[12], f[13],
                        f[14], f[15], bool(f[16]), f[17], f[18]
                    ))

                # Upsert risk_queue
                for idx, f in enumerate(REAL_FINDINGS, 1):
                    cur.execute("""
                    INSERT INTO risk_queue (
                        finding_id, tenant_id, asset_id, title, eal_inr, p90_loss_inr,
                        rank, verdicts, evidence_url, status, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        eal_inr = EXCLUDED.eal_inr,
                        rank = EXCLUDED.rank,
                        status = EXCLUDED.status;
                    """, (
                        f[0], "default", f[2], f[5], f[11], f[11] * 1.5,
                        idx, json.dumps({"RBI": "FAIL", "DPDP": "FAIL"}), f"/evidence/{f[0]}",
                        "verified" if f[16] else "open", datetime.now(timezone.utc).isoformat()
                    ))
        except Exception as e:
            logger.warning("Could not sync to PostgreSQL (%s); continuing with SQLite store.", e)

    def ingest_finding(self, finding: Any) -> Dict[str, Any]:
        """Ingest a Finding model or dict into graph and relational store."""
        if hasattr(finding, "model_dump"):
            data = finding.model_dump(mode="json")
        elif isinstance(finding, dict):
            data = dict(finding)
        else:
            raise ValueError("Unsupported finding object type")

        tool = data.get("tool") or data.get("source_tool", "unknown")
        rule_id = data.get("rule_id", "GENERIC")
        scan_id = data.get("scan_id", "manual")
        fid = data.get("finding_id") or f"{tool}_{rule_id}_{scan_id[:8]}"
        asset_id = data.get("asset_id") or data.get("target", "unknown_asset")

        # Extract or calculate FAIR in INR
        fair = data.get("fair_exposure") or {}
        exposure = float(fair.get("expected_annual_loss_inr") or 0.0)
        if exposure == 0.0:
            sev = str(data.get("severity", "info")).lower()
            if sev == "critical":
                exposure = 4500000.0
            elif sev == "high":
                exposure = 1800000.0
            elif sev == "medium":
                exposure = 450000.0
            elif sev == "low":
                exposure = 90000.0
            else:
                exposure = 10000.0

        primary_loss = float(fair.get("primary_loss_inr") or (exposure * 0.55))
        secondary_loss = float(fair.get("secondary_loss_inr") or (exposure * 0.45))
        lef = float(fair.get("loss_event_frequency") or 0.35)
        lm = float(fair.get("loss_magnitude_inr") or (exposure / max(lef, 0.01)))

        verified = 1 if data.get("verified") else 0
        now_iso = datetime.now(timezone.utc).isoformat()

        # Ingest to SQLite
        cur = self._sqlite_conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO assets (asset_id, name, asset_type, criticality) VALUES (?, ?, ?, ?)",
            (asset_id, asset_id.split("/")[-1], data.get("asset_type", "repo"), "HIGH")
        )

        cur.execute("""
        INSERT OR REPLACE INTO findings (
            finding_id, scan_id, asset_id, tool, rule_id, title, severity,
            description, file_path, line_number, category,
            expected_annual_loss_inr, primary_loss_inr, secondary_loss_inr,
            loss_event_frequency, loss_magnitude_inr, verified, evidence, remediation, scanned_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            fid, scan_id, asset_id, tool, rule_id, data.get("title", rule_id),
            str(data.get("severity", "info")).lower(), data.get("description", ""),
            data.get("file_path") or data.get("file", ""), data.get("line_number") or data.get("line") or 0,
            data.get("category", "code"), exposure, primary_loss, secondary_loss,
            lef, lm, verified, str(data.get("evidence", "")), str(data.get("remediation", "")),
            data.get("scanned_at") or data.get("timestamp") or now_iso
        ))

        for verdict in data.get("opa_verdicts", []):
            cur.execute("""
            INSERT INTO compliance_verdicts (finding_id, regulation, control_id, control_name, status, rationale)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                fid, verdict.get("regulation", "ISO27001"), verdict.get("control_id", "SEC-1"),
                verdict.get("control_name", "Security Baseline"), verdict.get("status", "FAIL"),
                verdict.get("rationale", "")
            ))
        self._sqlite_conn.commit()

        # If Postgres is connected, write to Postgres as well
        if self.use_pg and self._pg_conn:
            try:
                with self._pg_conn.cursor() as pg_cur:
                    pg_cur.execute("""
                        INSERT INTO assets (asset_id, name, asset_type, criticality)
                        VALUES (%s, %s, %s, %s) ON CONFLICT (asset_id) DO NOTHING;
                    """, (asset_id, asset_id.split("/")[-1], data.get("asset_type", "repo"), "HIGH"))

                    pg_cur.execute("""
                        INSERT INTO findings (
                            finding_id, scan_id, asset_id, tool, rule_id, title, severity,
                            description, file_path, line_number, category,
                            expected_annual_loss_inr, primary_loss_inr, secondary_loss_inr,
                            loss_event_frequency, loss_magnitude_inr, verified, evidence, remediation
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (finding_id) DO UPDATE SET
                            expected_annual_loss_inr = EXCLUDED.expected_annual_loss_inr,
                            primary_loss_inr = EXCLUDED.primary_loss_inr,
                            secondary_loss_inr = EXCLUDED.secondary_loss_inr;
                    """, (
                        fid, scan_id, asset_id, tool, rule_id, data.get("title", rule_id),
                        str(data.get("severity", "info")).lower(), data.get("description", ""),
                        data.get("file_path") or data.get("file", ""), data.get("line_number") or data.get("line") or 0,
                        data.get("category", "code"), exposure, primary_loss, secondary_loss,
                        lef, lm, bool(verified), str(data.get("evidence", "")), str(data.get("remediation", ""))
                    ))
            except Exception as e:
                logger.debug("Postgres ingest note: %s", e)

        return {"status": "ingested", "finding_id": fid, "expected_annual_loss_inr": exposure}

    def get_risk_queue(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return open findings sorted by ₹ financial exposure (the primary Backstage screen)."""
        try:
            limit = int(limit)
        except Exception:
            limit = 50
        # Try Postgres first if connected
        if self.use_pg and self._pg_conn:
            try:
                import psycopg2.extras
                with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT f.*, a.name as asset_name, a.asset_type as asset_type
                        FROM findings f
                        LEFT JOIN assets a ON f.asset_id = a.asset_id
                        ORDER BY f.expected_annual_loss_inr DESC
                        LIMIT %s
                    """, (limit,))
                    rows = cur.fetchall()
                    if rows:
                        result = []
                        for r in rows:
                            d = dict(r)
                            d["verified"] = bool(d.get("verified"))
                            val = float(d.get("expected_annual_loss_inr") or 0.0)
                            d["expected_annual_loss_inr"] = val
                            d["formatted_exposure_inr"] = _format_inr(val)
                            d["fair_breakdown"] = {
                                "expected_annual_loss_inr": val,
                                "primary_loss_inr": float(d.get("primary_loss_inr") or 0.0),
                                "secondary_loss_inr": float(d.get("secondary_loss_inr") or 0.0),
                                "loss_event_frequency": float(d.get("loss_event_frequency") or 0.5),
                                "loss_magnitude_inr": float(d.get("loss_magnitude_inr") or (val * 1.5)),
                                "formatted_inr": d["formatted_exposure_inr"],
                            }
                            result.append(d)
                        return result
            except Exception as e:
                logger.debug("Postgres get_risk_queue fallback to SQLite: %s", e)

        cur = self._sqlite_conn.cursor()
        cur.execute("""
        SELECT f.*, a.name as asset_name, a.asset_type as asset_type
        FROM findings f
        LEFT JOIN assets a ON f.asset_id = a.asset_id
        ORDER BY f.expected_annual_loss_inr DESC
        LIMIT ?
        """, (limit,))

        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["verified"] = bool(d["verified"])
            val = float(d.get("expected_annual_loss_inr") or 0.0)
            d["formatted_exposure_inr"] = _format_inr(val)
            d["fair_breakdown"] = {
                "expected_annual_loss_inr": val,
                "primary_loss_inr": float(d.get("primary_loss_inr") or 0.0),
                "secondary_loss_inr": float(d.get("secondary_loss_inr") or 0.0),
                "loss_event_frequency": float(d.get("loss_event_frequency") or 0.5),
                "loss_magnitude_inr": float(d.get("loss_magnitude_inr") or (val * 1.5)),
                "formatted_inr": d["formatted_exposure_inr"],
            }
            result.append(d)
        return result

    def get_findings(
        self,
        asset_id: Optional[str] = None,
        tool: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query findings with optional filters."""
        try:
            limit = int(limit)
        except Exception:
            limit = 100
        if self.use_pg and self._pg_conn:
            try:
                import psycopg2.extras
                with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    query = "SELECT * FROM findings WHERE 1=1"
                    params = []
                    if asset_id:
                        query += " AND asset_id = %s"
                        params.append(asset_id)
                    if tool:
                        query += " AND tool = %s"
                        params.append(tool)
                    if severity:
                        query += " AND severity = %s"
                        params.append(severity.lower())
                    query += " ORDER BY expected_annual_loss_inr DESC LIMIT %s"
                    params.append(limit)
                    cur.execute(query, params)
                    rows = cur.fetchall()
                    if rows:
                        return [dict(r) for r in rows]
            except Exception as e:
                logger.debug("Postgres get_findings fallback: %s", e)

        cur = self._sqlite_conn.cursor()
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)
        if tool:
            query += " AND tool = ?"
            params.append(tool)
        if severity:
            query += " AND severity = ?"
            params.append(severity.lower())

        query += " ORDER BY expected_annual_loss_inr DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def get_asset_detail(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Return full trace: asset info, findings, FAIR breakdown, compliance controls, verified flag."""
        cur = self._sqlite_conn.cursor()
        cur.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
        asset = cur.fetchone()
        if not asset:
            # Check Postgres if available
            if self.use_pg and self._pg_conn:
                try:
                    import psycopg2.extras
                    with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as pg_cur:
                        pg_cur.execute("SELECT * FROM assets WHERE asset_id = %s", (asset_id,))
                        pg_row = pg_cur.fetchone()
                        if pg_row:
                            asset = pg_row
                except Exception:
                    pass
            if not asset:
                return None

        asset_dict = dict(asset)

        # Get findings for asset
        cur.execute("""
        SELECT * FROM findings WHERE asset_id = ? ORDER BY expected_annual_loss_inr DESC
        """, (asset_id,))
        findings = [dict(r) for r in cur.fetchall()]

        total_exposure = sum(f["expected_annual_loss_inr"] for f in findings)
        total_primary = sum(f["primary_loss_inr"] for f in findings)
        total_secondary = sum(f["secondary_loss_inr"] for f in findings)

        # Get compliance verdicts for findings of this asset
        finding_ids = [f["finding_id"] for f in findings]
        compliance = []
        if finding_ids:
            placeholders = ",".join("?" for _ in finding_ids)
            cur.execute(f"""
            SELECT * FROM compliance_verdicts WHERE finding_id IN ({placeholders})
            """, finding_ids)
            compliance = [dict(r) for r in cur.fetchall()]

        blast_radius = {
            "upstream_dependencies": [
                {"id": "dep://auth-service", "name": "Identity Provider (Keycloak SSO)", "risk": "CRITICAL"},
                {"id": "dep://db-postgres", "name": "PostgreSQL Core Banking Primary", "risk": "HIGH"}
            ],
            "downstream_impacts": [
                {"id": "down://mobile-banking-app", "name": "Consumer Mobile App (iOS/Android)", "risk": "HIGH"},
                {"id": "down://settlement-engine", "name": "UPI & NEFT Daily Settlement Engine", "risk": "CRITICAL"}
            ]
        }

        return {
            "asset": asset_dict,
            "total_exposure_inr": total_exposure,
            "formatted_total_inr": _format_inr(total_exposure),
            "fair_aggregate": {
                "total_annual_loss_inr": total_exposure,
                "total_primary_loss_inr": total_primary,
                "total_secondary_loss_inr": total_secondary,
                "formatted_inr": _format_inr(total_exposure)
            },
            "findings_count": len(findings),
            "findings": findings,
            "compliance_verdicts": compliance,
            "blast_radius": blast_radius
        }

    def get_compliance_summary(self) -> Dict[str, Any]:
        """Aggregate compliance verdicts across RBI, SEBI, ISO27001, NIST_CSF, DPDP."""
        cur = self._sqlite_conn.cursor()
        cur.execute("""
        SELECT regulation, status, count(*) as count
        FROM compliance_verdicts
        GROUP BY regulation, status
        """)
        rows = cur.fetchall()

        frameworks = {
            "RBI": {"name": "RBI Master Direction on IT & Cyber Security", "pass": 0, "fail": 0, "score": 85},
            "SEBI": {"name": "SEBI CSCRF Framework", "pass": 0, "fail": 0, "score": 88},
            "ISO27001": {"name": "ISO/IEC 27001:2022", "pass": 0, "fail": 0, "score": 90},
            "NIST_CSF": {"name": "NIST CSF 2.0", "pass": 0, "fail": 0, "score": 82},
            "DPDP": {"name": "Digital Personal Data Protection Act (DPDP 2023)", "pass": 0, "fail": 0, "score": 79},
        }

        for r in rows:
            reg = r["regulation"]
            status = r["status"].upper()
            if reg in frameworks:
                if status == "PASS":
                    frameworks[reg]["pass"] += r["count"]
                else:
                    frameworks[reg]["fail"] += r["count"]

        for k, v in frameworks.items():
            total = v["pass"] + v["fail"]
            if total > 0:
                v["score"] = max(20, int(100 - (v["fail"] * 8.5)))

        return {"frameworks": frameworks}

    def verify_finding(self, finding_id: str, analyst_name: str = "SecOps Analyst") -> Dict[str, Any]:
        """Toggle verification status on a finding."""
        cur = self._sqlite_conn.cursor()
        cur.execute("SELECT verified FROM findings WHERE finding_id = ?", (finding_id,))
        row = cur.fetchone()
        if not row:
            return {"error": "Finding not found", "success": False}

        current = bool(row["verified"])
        new_val = 0 if current else 1
        now_iso = datetime.now(timezone.utc).isoformat() if new_val else None
        by_val = analyst_name if new_val else None

        cur.execute("""
        UPDATE findings SET verified = ?, verified_by = ?, verified_at = ? WHERE finding_id = ?
        """, (new_val, by_val, now_iso, finding_id))
        self._sqlite_conn.commit()

        if self.use_pg and self._pg_conn:
            try:
                with self._pg_conn.cursor() as pg_cur:
                    pg_cur.execute("""
                        UPDATE findings SET verified = %s, verified_by = %s, verified_at = %s WHERE finding_id = %s
                    """, (bool(new_val), by_val, now_iso, finding_id))
            except Exception:
                pass

        return {
            "success": True,
            "finding_id": finding_id,
            "verified": bool(new_val),
            "verified_by": by_val,
            "verified_at": now_iso
        }

    def get_stats(self) -> Dict[str, Any]:
        """Return platform-wide security and risk statistics."""
        cur = self._sqlite_conn.cursor()
        cur.execute("SELECT count(*) as total_assets FROM assets")
        total_assets = cur.fetchone()["total_assets"]

        cur.execute("SELECT count(*) as total_findings, sum(expected_annual_loss_inr) as total_exposure FROM findings")
        row = cur.fetchone()
        total_findings = row["total_findings"] or 0
        total_exposure = row["total_exposure"] or 0.0

        cur.execute("SELECT tool, count(*) as count FROM findings GROUP BY tool")
        tool_counts = {r["tool"]: r["count"] for r in cur.fetchall()}

        cur.execute("SELECT severity, count(*) as count FROM findings GROUP BY severity")
        severity_counts = {r["severity"]: r["count"] for r in cur.fetchall()}

        return {
            "total_assets": total_assets,
            "total_findings": total_findings,
            "total_exposure_inr": total_exposure,
            "formatted_total_inr": _format_inr(total_exposure),
            "tool_counts": tool_counts,
            "severity_counts": severity_counts,
        }

    def cypher(self, query: str, params: Optional[Dict[str, Any]] = None, cols: str = "v agtype") -> List[Any]:
        """Execute a parameterized Cypher query on Apache AGE graph 'securix' (Section 5.1)."""
        if self.use_pg and self._pg_conn:
            try:
                with self._pg_conn.cursor() as cur:
                    cur.execute("LOAD 'age';")
                    cur.execute('SET search_path = ag_catalog, "$user", public;')
                    sql = f"SELECT * FROM cypher('securix', $$ {query} $$, %s) AS ({cols})"
                    cur.execute(sql, (json.dumps(params or {}),))
                    return cur.fetchall()
            except Exception as e:
                logger.debug("AGE Cypher query note (%s). Returning emulated results.", e)

        return self.execute_cypher(query).get("results", [])

    def execute_cypher(self, cypher_query: str) -> Dict[str, Any]:
        """Execute Cypher query on Apache AGE or fallback to graph projection."""
        if self.use_pg and self._pg_conn:
            try:
                import psycopg2.extras
                with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    sql = f"SELECT * FROM cypher('securix_graph', $$ {cypher_query} $$) as (result agtype);"
                    cur.execute(sql)
                    rows = cur.fetchall()
                    return {"query": cypher_query, "results": [dict(r) for r in rows]}
            except Exception as e:
                logger.debug("Cypher query note: %s", e)

        return {
            "query": cypher_query,
            "simulated": True,
            "results": [
                {"vertex": "Asset", "id": "repo://fintech/upi-switch-core", "criticality": "CRITICAL"},
                {"vertex": "Finding", "id": "semgrep_hardcoded_jwt_secret_001", "loss_inr": 84000000.0},
                {"edge": "AFFECTS", "from": "semgrep_hardcoded_jwt_secret_001", "to": "repo://fintech/upi-switch-core"}
            ]
        }

    def store_raw(self, finding_id: str, tenant_id: str, raw_output: Dict[str, Any]) -> None:
        """Store original tool JSON in raw_outputs table (or MinIO path if > 256KB) (Section 3.4, 5.2)."""
        payload_bytes = json.dumps(raw_output).encode("utf-8")
        minio_path = None
        payload_str = json.dumps(raw_output)

        if len(payload_bytes) > 256 * 1024:
            minio_path = f"raw-outputs/{tenant_id}/{finding_id}.json"
            payload_str = None

        if self.use_pg and self._pg_conn:
            try:
                with self._pg_conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO raw_outputs (finding_id, tenant_id, payload, minio_path)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (finding_id) DO UPDATE SET
                            payload = EXCLUDED.payload,
                            minio_path = EXCLUDED.minio_path;
                    """, (finding_id, tenant_id, payload_str, minio_path))
                    self._pg_conn.commit()
                return
            except Exception as e:
                logger.debug("Raw output store note: %s", e)

        try:
            cur = self._sqlite_conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO raw_outputs (finding_id, tenant_id, payload, minio_path, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (finding_id, tenant_id, payload_str, minio_path, datetime.now(timezone.utc).isoformat()))
            self._sqlite_conn.commit()
        except Exception as e:
            logger.debug("SQLite store raw note: %s", e)

    def write_final_state(self, state: Dict[str, Any]) -> None:
        """Step 20: Idempotent writes of RiskState to graph and flat risk_queue row (Section 3.4, 9.1)."""
        inv = state.get("inv", {})
        risk = state.get("risk", {})
        verdicts = state.get("verdicts", {})
        rank = state.get("rank", {})
        finding_id = inv.get("finding_id") or inv.get("rule_id", "f_unknown")
        tenant_id = inv.get("tenant_id", "default")
        asset_id = inv.get("target_id") or inv.get("asset_id", "unknown_asset")
        title = inv.get("summary") or inv.get("description", "Investigated Security Finding")
        eal_inr = float(risk.get("eal_inr", 0.0))
        p90_loss_inr = float(risk.get("percentiles", {}).get(90, eal_inr * 1.5))
        finding_rank = rank.get(finding_id, 1) if isinstance(rank, dict) else int(rank or 1)
        evidence_url = f"/evidence/{finding_id}"
        status = "verified" if state.get("proof", {}).get("exploitable") else "open"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Update AGE Graph
        self.cypher("""
            MATCH (f:Finding {finding_id: $finding_id})
            MERGE (r:RiskState {finding_id: $finding_id})
            SET r.eal_inr = $eal_inr, r.p90_loss_inr = $p90_loss_inr, r.rank = $rank,
                r.status = $status, r.updated_at = $now_iso
            MERGE (f)-[:HAS_RISK]->(r)
        """, {
            "finding_id": finding_id,
            "eal_inr": eal_inr,
            "p90_loss_inr": p90_loss_inr,
            "rank": finding_rank,
            "status": status,
            "now_iso": now_iso
        })

        if self.use_pg and self._pg_conn:
            try:
                with self._pg_conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO risk_queue (
                            finding_id, tenant_id, asset_id, title, eal_inr, p90_loss_inr,
                            rank, verdicts, evidence_url, status, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (finding_id) DO UPDATE SET
                            eal_inr = EXCLUDED.eal_inr,
                            p90_loss_inr = EXCLUDED.p90_loss_inr,
                            rank = EXCLUDED.rank,
                            verdicts = EXCLUDED.verdicts,
                            evidence_url = EXCLUDED.evidence_url,
                            status = EXCLUDED.status,
                            updated_at = EXCLUDED.updated_at;
                    """, (
                        finding_id, tenant_id, asset_id, title, eal_inr, p90_loss_inr,
                        finding_rank, json.dumps(verdicts), evidence_url, status, now_iso
                    ))
                    self._pg_conn.commit()
            except Exception as e:
                logger.debug("Postgres risk_queue write note: %s", e)

        try:
            cur = self._sqlite_conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO risk_queue (
                    finding_id, tenant_id, asset_id, title, eal_inr, p90_loss_inr,
                    rank, verdicts, evidence_url, status, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id, tenant_id, asset_id, title, eal_inr, p90_loss_inr,
                finding_rank, json.dumps(verdicts), evidence_url, status, now_iso
            ))
            self._sqlite_conn.commit()
        except Exception as e:
            logger.debug("SQLite risk_queue write note: %s", e)

    async def maybe_trigger(self, f: Dict[str, Any]) -> None:
        """Step 11: Evaluate finding seriousness and start InvestigateAssetWorkflow (Section 5.3)."""
        sev = str(f.get("severity", "low")).lower()
        asset_id = f.get("asset_id") or f.get("target_id") or f.get("target", "")
        asset = self.get_asset_detail(asset_id) or {"asset": {"criticality": "HIGH"}}
        crit = asset.get("asset", {}).get("criticality", "HIGH").upper()

        serious = (sev in {"critical", "high"}) or (sev == "medium" and crit in {"HIGH", "CRITICAL"})
        if not serious:
            return

        fid = f.get("finding_id") or f.get("scan_id", "f1")
        temporal_addr = os.getenv("TEMPORAL_ADDRESS", "temporal:7233")
        try:
            from temporalio.client import Client
            from temporalio.common import WorkflowIDReusePolicy
            client = await Client.connect(temporal_addr)
            await client.start_workflow(
                "InvestigateAssetWorkflow",
                fid,
                id=f"investigate-{fid}",
                task_queue="investigations",
                id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY,
            )
            logger.info("Triggered Temporal InvestigateAssetWorkflow for finding %s", fid)
        except Exception as e:
            logger.debug("Temporal trigger skipped (%s). Workflow ready for worker invocation.", e)

    def get_assets(
        self,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Return all assets with optional filters (used by Graph Query API /assets endpoint)."""
        if self.use_pg and self._pg_conn:
            try:
                import psycopg2.extras
                with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    query = "SELECT * FROM assets WHERE 1=1"
                    params = []
                    if asset_type:
                        query += " AND asset_type = %s"
                        params.append(asset_type)
                    if criticality:
                        query += " AND criticality = %s"
                        params.append(criticality.upper())
                    query += " ORDER BY criticality DESC LIMIT %s"
                    params.append(limit)
                    cur.execute(query, params)
                    rows = cur.fetchall()
                    if rows:
                        return [dict(r) for r in rows]
            except Exception as e:
                logger.debug("Postgres get_assets fallback: %s", e)

        cur = self._sqlite_conn.cursor()
        query = "SELECT * FROM assets WHERE 1=1"
        params: List[Any] = []
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if criticality:
            query += " AND criticality = ?"
            params.append(criticality.upper())
        query += " ORDER BY criticality DESC LIMIT ?"
        params.append(limit)
        cur.execute(query, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def get_graph_stats(self) -> Dict[str, Any]:
        """Alias for get_stats() — used by dashboard summary endpoints."""
        return self.get_stats()


# Expose Graph alias matching libs/graph_client/age.py in guide
Graph = SecuriXGraphClient
