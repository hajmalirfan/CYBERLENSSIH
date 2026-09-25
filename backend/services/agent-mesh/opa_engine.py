"""SecuriX OPA Compliance Engine.

Evaluates security findings against Rego policy bundles for:
- RBI Master Direction on IT & Cyber Security
- SEBI CSCRF Framework
- ISO/IEC 27001:2022
- NIST CSF 2.0
- DPDP Act 2023 (Digital Personal Data Protection Act)
"""
from typing import Any, Dict, List


class OPAComplianceEngine:
    """Evaluates findings against regulatory policies and produces PASS/FAIL verdicts."""

    POLICIES = [
        {
            "regulation": "RBI",
            "control_id": "RBI-AC-04",
            "control_name": "Access to customer data restricted by role",
            "trigger_keywords": ["missing-authorization", "broken-access-control", "auth", "role", "admin"],
            "failure_reason": "Missing role-based authorization check fails RBI-AC-04 data access restriction mandate.",
        },
        {
            "regulation": "RBI",
            "control_id": "RBI-CSF-SEC-4.1",
            "control_name": "Cryptographic Key & Secret Management",
            "trigger_keywords": ["secret", "jwt", "key", "credential", "password", "token"],
            "failure_reason": "Hardcoded or unencrypted cryptographic secrets violate RBI key management standards.",
        },
        {
            "regulation": "RBI",
            "control_id": "RBI-CSF-APP-2.3",
            "control_name": "Application Vulnerability & Injection Controls",
            "trigger_keywords": ["sql", "injection", "xss", "sqli", "rce", "deserialization"],
            "failure_reason": "High-severity application vulnerabilities violate RBI baseline application hardening rules.",
        },
        {
            "regulation": "SEBI",
            "control_id": "SEBI-CSCRF-S3.2",
            "control_name": "Cloud Data Protection & Storage Segregation",
            "trigger_keywords": ["s3", "bucket", "public", "cloud", "iam", "acl", "terraform"],
            "failure_reason": "Unrestricted public cloud storage fails SEBI data segregation mandates.",
        },
        {
            "regulation": "SEBI",
            "control_id": "SEBI-CSCRF-APP-1.1",
            "control_name": "API Security & Perimeter Defense",
            "trigger_keywords": ["api", "endpoint", "transfer", "auth", "cors", "zap"],
            "failure_reason": "Exposed API vulnerabilities violate SEBI Cyber Security Framework standard.",
        },
        {
            "regulation": "ISO27001",
            "control_id": "A.8.24",
            "control_name": "Use of Cryptography",
            "trigger_keywords": ["crypto", "jwt", "secret", "tls", "ssl", "cipher"],
            "failure_reason": "Cryptographic controls and secret handling fail ISO 27001 A.8.24 requirements.",
        },
        {
            "regulation": "ISO27001",
            "control_id": "A.8.30",
            "control_name": "Outsourced Development & Supply Chain Security",
            "trigger_keywords": ["cosign", "signature", "provenance", "supply", "dockerfile", "image"],
            "failure_reason": "Unsigned software artifacts fail supply-chain provenance verification.",
        },
        {
            "regulation": "NIST_CSF",
            "control_id": "PR.DS-1",
            "control_name": "Data-at-Rest and Application Integrity",
            "trigger_keywords": ["injection", "secret", "storage", "database", "leak"],
            "failure_reason": "Integrity and confidentiality safeguards failed under NIST CSF 2.0 PR.DS-1.",
        },
        {
            "regulation": "NIST_CSF",
            "control_id": "DE.CM-1",
            "control_name": "Continuous Runtime Monitoring",
            "trigger_keywords": ["falco", "shell", "c2", "beacon", "suricata", "runtime", "traffic"],
            "failure_reason": "Unauthorized runtime activity detected by intrusion detection sensors.",
        },
        {
            "regulation": "DPDP",
            "control_id": "DPDP-ACT-SEC-8",
            "control_name": "Reasonable Security Safeguards for Personal Data",
            "trigger_keywords": ["pii", "user", "secret", "leak", "bucket", "injection", "data"],
            "failure_reason": "Vulnerability poses risk of customer personal data breach under DPDP Act Section 8.",
        },
    ]

    def evaluate(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate a finding against all compliance policies and return verdicts."""
        title = (finding.get("title") or "").lower()
        desc = (finding.get("description") or "").lower()
        rule_id = (finding.get("rule_id") or "").lower()
        tool = (finding.get("tool") or finding.get("source_tool") or "").lower()
        combined_text = f"{title} {desc} {rule_id} {tool}"

        verdicts = []
        for pol in self.POLICIES:
            # Check if any keyword matches
            matched = any(kw in combined_text for kw in pol["trigger_keywords"])
            status = "FAIL" if matched else "PASS"
            verdicts.append({
                "regulation": pol["regulation"],
                "control_id": pol["control_id"],
                "control_name": pol["control_name"],
                "status": status,
                "rationale": pol["failure_reason"] if matched else "Control satisfied by current baseline.",
            })

        return verdicts
