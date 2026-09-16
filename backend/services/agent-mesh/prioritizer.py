"""SecuriX Prioritization Agent.

Ranks vulnerabilities by contextual business impact:
FAIR ₹ Financial Exposure + Asset Criticality + Exploitability.
Replaces simplistic Low/Medium/High triage with defensible financial prioritization.
"""
from typing import Any, Dict, List


class PrioritizationAgent:
    """Prioritizes findings based on financial exposure and contextual business criticality."""

    def prioritize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Compute composite risk priority score for a single finding."""
        fair = finding.get("fair_exposure", {})
        loss_inr = float(fair.get("expected_annual_loss_inr", 0.0))

        severity = str(finding.get("severity", "info")).lower()
        criticality = str(finding.get("criticality", "HIGH")).upper()

        # Score components (0-100)
        # 1. Financial exposure score (logarithmic scale up to ₹1 Cr)
        exposure_score = min(100.0, (loss_inr / 10000000.0) * 100.0) if loss_inr > 0 else 10.0

        # 2. Criticality factor
        crit_weights = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}
        crit_score = crit_weights.get(criticality, 0.7) * 100.0

        # 3. Severity factor
        sev_weights = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
        sev_score = sev_weights.get(severity, 0.5) * 100.0

        # Composite score
        composite = (exposure_score * 0.50) + (crit_score * 0.30) + (sev_score * 0.20)

        # Priority tier
        if composite >= 75:
            tier = "P1 - Critical Business Exposure"
            action = "Immediate Remediation within 24 Hours. Financial loss exceeds threshold."
        elif composite >= 50:
            tier = "P2 - High Financial Risk"
            action = "Remediate in Current Sprint (7 Days)."
        elif composite >= 25:
            tier = "P3 - Moderate Exposure"
            action = "Scheduled Maintenance (30 Days)."
        else:
            tier = "P4 - Low / Informational"
            action = "Review during periodic hardening cycle."

        return {
            "finding_id": finding.get("finding_id") or finding.get("title"),
            "composite_score": round(composite, 1),
            "priority_tier": tier,
            "recommended_action": action,
            "expected_annual_loss_inr": loss_inr,
            "exposure_factor": round(exposure_score, 1),
            "criticality_factor": round(crit_score, 1),
        }

    def rank_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank an entire list of findings in descending order of business priority."""
        scored = [
            {**f, "priority": self.prioritize_finding(f)}
            for f in findings
        ]
        scored.sort(key=lambda x: x["priority"]["composite_score"], reverse=True)
        return scored
