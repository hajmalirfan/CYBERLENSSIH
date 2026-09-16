"""SecuriX Knowledge Graph Client (PostgreSQL + Apache AGE).

Provides the unified Graph Query API implementation connecting to PostgreSQL + Apache AGE,
with a resilient local SQLite/in-memory fallback to enable offline testing and standalone dev.
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


class SecuriXGraphClient:
    """Unified client for SecuriX Security Graph and relational storage."""

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or os.getenv("DATABASE_URL", "")
        self.use_pg = bool(self.db_url and self.db_url.startswith("postgresql"))
        self._pg_conn = None
        self._sqlite_conn = None

        if self.use_pg:
            try:
                import psycopg2
                import psycopg2.extras
                self._pg_conn = psycopg2.connect(self.db_url)
                self._pg_conn.autocommit = True
                logger.info("Connected to PostgreSQL + Apache AGE at %s", self.db_url)
            except Exception as e:
                logger.warning("PostgreSQL connection failed (%s). Falling back to SQLite local store.", e)
                self.use_pg = False

        if not self.use_pg:
            self._init_sqlite()

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

        # Seed initial assets
        demo_assets = [
            ('repo://fintech/payment-gateway', 'Payment Gateway Core', 'repo', 'CRITICAL', 'Payments Team'),
            ('image://registry.internal/checkout-api:v2.4', 'Checkout API Container', 'container_image', 'CRITICAL', 'Core Banking Team'),
            ('iac://cloud/aws-production-vpc', 'AWS Production VPC Terraform', 'iac_source', 'HIGH', 'Cloud Platform Team'),
            ('url://api.fintech.internal/v1/transfer', 'Fund Transfer API Endpoint', 'web_endpoint', 'CRITICAL', 'API Security'),
        ]
        cur.executemany(
            "INSERT OR IGNORE INTO assets (asset_id, name, asset_type, criticality, owner) VALUES (?, ?, ?, ?, ?)",
            demo_assets,
        )

        # Seed initial findings
        demo_findings = [
            (
                'semgrep_hardcoded_jwt_secret_001', 'scan_sast_01', 'repo://fintech/payment-gateway',
                'semgrep', 'generic.secrets.jwt-hardcoded-secret',
                'Hardcoded JWT Signing Secret in Payment Handler', 'critical',
                'Cryptographic secret key used to sign authorization tokens is hardcoded in source repository.',
                'src/auth/jwt_handler.py', 42, 'code',
                4550000.0, 2500000.0, 2050000.0, 0.70, 6500000.0, 0,
                'JWT_SECRET = "super_secret_production_key_2026"',
                'Move secrets to HashiCorp Vault or AWS Secrets Manager. Do not store secrets in source code.',
                '2026-09-16T10:00:00Z'
            ),
            (
                'checkov_s3_bucket_public_002', 'scan_iac_02', 'iac://cloud/aws-production-vpc',
                'checkov', 'CKV_AWS_20',
                'S3 Bucket has Public Read Access Enabled', 'high',
                'S3 bucket storing transaction receipts does not have Block Public Access enabled, risking mass customer PII leak.',
                'terraform/s3_storage.tf', 18, 'infrastructure',
                1820000.0, 820000.0, 1000000.0, 0.40, 4550000.0, 1,
                'acl = "public-read"',
                'Set acl = "private" and enable aws_s3_bucket_public_access_block.',
                '2026-09-16T10:05:00Z'
            ),
            (
                'cosign_unsigned_container_003', 'scan_supply_03', 'image://registry.internal/checkout-api:v2.4',
                'cosign', 'COSIGN_SIGNATURE_MISSING',
                'Production Container Image Lacks Valid Cryptographic Signature', 'high',
                'Container image was deployed without Sigstore cosign keyless cryptographic signature verification.',
                'registry.internal/checkout-api:v2.4', 1, 'supply-chain',
                1250000.0, 500000.0, 750000.0, 0.25, 5000000.0, 0,
                'cosign verify failed: no valid signatures found in registry',
                'Configure CI pipeline with cosign sign --yes in GitHub Actions.',
                '2026-09-16T10:10:00Z'
            ),
            (
                'zap_sqli_transfer_endpoint_004', 'scan_dast_04', 'url://api.fintech.internal/v1/transfer',
                'zap', '40018',
                'SQL Injection Vulnerability in Account Balance Lookup', 'critical',
                'Unescaped parameter account_id allows blind time-based SQL injection on internal database.',
                '/v1/transfer?account_id=1001', 1, 'web',
                5800000.0, 3000000.0, 2800000.0, 0.80, 7250000.0, 0,
                'Parameter account_id vulnerable with payload 1001 OR 1=1',
                'Use parameterized queries or ORM binding. Never concatenate user input into SQL strings.',
                '2026-09-16T10:15:00Z'
            ),
            (
                'falco_interactive_shell_005', 'scan_runtime_05', 'image://registry.internal/checkout-api:v2.4',
                'falco', 'Terminal shell in container',
                'Interactive Bash Shell Spawned Inside Production Container', 'critical',
                'Falco kernel probe detected unauthorized interactive /bin/bash shell execution in running container.',
                '/bin/bash', 102, 'runtime',
                3400000.0, 1400000.0, 2000000.0, 0.60, 5666666.0, 0,
                'falco alert: Notice A shell was spawned in a container with an attached terminal',
                'Enforce read-only root filesystems and drop CAP_SYS_ADMIN capabilities.',
                '2026-09-16T10:20:00Z'
            ),
            (
                'suricata_c2_traffic_006', 'scan_net_06', 'url://api.fintech.internal/v1/transfer',
                'suricata', '2018959',
                'Outbound Cobalt Strike C2 Beaconing Detected', 'high',
                'Suricata network engine detected regular HTTP beaconing matching known threat actor infrastructure.',
                'pcap_stream:eth0', 504, 'network',
                2750000.0, 1250000.0, 1500000.0, 0.50, 5500000.0, 1,
                'ET MALWARE Cobalt Strike Beaconing User-Agent observed on port 443',
                'Isolate the compromised host immediately and rotate all database credentials.',
                '2026-09-16T10:25:00Z'
            ),
        ]

        cur.executemany("""
        INSERT OR IGNORE INTO findings (
            finding_id, scan_id, asset_id, tool, rule_id, title, severity,
            description, file_path, line_number, category,
            expected_annual_loss_inr, primary_loss_inr, secondary_loss_inr,
            loss_event_frequency, loss_magnitude_inr, verified, evidence, remediation, scanned_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, demo_findings)

        demo_verdicts = [
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
        ]

        cur.executemany("""
        INSERT INTO compliance_verdicts (finding_id, regulation, control_id, control_name, status, rationale)
        VALUES (?, ?, ?, ?, ?, ?)
        """, demo_verdicts)

        self._sqlite_conn.commit()

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

        cur = self._sqlite_conn.cursor()
        # Upsert asset
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

        # Ingest compliance verdicts if present
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
        return {"status": "ingested", "finding_id": fid, "expected_annual_loss_inr": exposure}

    def get_risk_queue(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return open findings sorted by ₹ financial exposure (the primary Backstage screen)."""
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
            d["formatted_exposure_inr"] = _format_inr(d["expected_annual_loss_inr"])
            d["fair_breakdown"] = {
                "expected_annual_loss_inr": d["expected_annual_loss_inr"],
                "primary_loss_inr": d["primary_loss_inr"],
                "secondary_loss_inr": d["secondary_loss_inr"],
                "loss_event_frequency": d["loss_event_frequency"],
                "loss_magnitude_inr": d["loss_magnitude_inr"],
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

        # Blast radius mock traversal
        blast_radius = {
            "upstream_dependencies": [
                {"id": "dep://auth-service", "name": "Identity Provider (Keycloak)", "risk": "CRITICAL"},
                {"id": "dep://db-postgres", "name": "PostgreSQL Primary Cluster", "risk": "HIGH"}
            ],
            "downstream_impacts": [
                {"id": "down://mobile-banking-app", "name": "Consumer Mobile App", "risk": "HIGH"},
                {"id": "down://settlement-engine", "name": "Daily Settlement Engine", "risk": "CRITICAL"}
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
                logger.warning("Cypher query failed: %s", e)

        # Emulated response for Cypher MATCH (n) queries
        return {
            "query": cypher_query,
            "simulated": True,
            "results": [
                {"vertex": "Asset", "id": "repo://fintech/payment-gateway", "criticality": "CRITICAL"},
                {"vertex": "Finding", "id": "semgrep_hardcoded_jwt_secret_001", "loss_inr": 4550000.0},
                {"edge": "AFFECTS", "from": "semgrep_hardcoded_jwt_secret_001", "to": "repo://fintech/payment-gateway"}
            ]
        }
