"""SecuriX PyFair Quantitative Risk Engine.

Implements Factor Analysis of Information Risk (FAIR) Monte Carlo simulation
to convert technical vulnerability findings into financial loss exposure in Indian Rupees (₹).
"""
import random
from typing import Any, Dict, List, Optional


def _format_inr(val: float) -> str:
    """Format numeric loss to Indian Rupees (₹) string representation."""
    if val >= 10000000:
        return f"₹{val / 10000000:.2f} Cr"
    elif val >= 100000:
        return f"₹{val / 100000:.2f} Lakhs"
    elif val >= 1000:
        return f"₹{val / 1000:.1f} K"
    else:
        return f"₹{val:.0f}"


class FAIRSimulationEngine:
    """FAIR Risk Quantification Engine running Monte Carlo loss distribution simulations."""

    SEVERITY_MULTIPLIERS = {
        "critical": {"tef": (4.0, 12.0), "vuln": (0.50, 0.85), "mag_base": (4000000.0, 10000000.0)},
        "high": {"tef": (2.0, 6.0), "vuln": (0.30, 0.55), "mag_base": (1500000.0, 4500000.0)},
        "medium": {"tef": (1.0, 3.0), "vuln": (0.15, 0.30), "mag_base": (400000.0, 1200000.0)},
        "low": {"tef": (0.5, 1.5), "vuln": (0.05, 0.15), "mag_base": (80000.0, 300000.0)},
        "info": {"tef": (0.1, 0.5), "vuln": (0.01, 0.05), "mag_base": (10000.0, 50000.0)},
    }

    CRITICALITY_FACTORS = {
        "CRITICAL": 1.8,
        "HIGH": 1.2,
        "MEDIUM": 0.8,
        "LOW": 0.4,
    }

    def simulate(
        self,
        severity: str = "high",
        criticality: str = "HIGH",
        iterations: int = 1000
    ) -> Dict[str, Any]:
        """Run Monte Carlo simulation for finding risk exposure in INR."""
        sev_params = self.SEVERITY_MULTIPLIERS.get(severity.lower(), self.SEVERITY_MULTIPLIERS["medium"])
        crit_factor = self.CRITICALITY_FACTORS.get(criticality.upper(), 1.0)

        tef_min, tef_max = sev_params["tef"]
        vuln_min, vuln_max = sev_params["vuln"]
        mag_min, mag_max = sev_params["mag_base"]

        annual_losses = []
        for _ in range(iterations):
            tef = random.uniform(tef_min, tef_max)
            vuln = random.uniform(vuln_min, vuln_max)
            lef = tef * vuln  # Loss Event Frequency

            primary_loss = random.uniform(mag_min, mag_max) * crit_factor * 0.55
            secondary_loss = random.uniform(mag_min, mag_max) * crit_factor * 0.45
            total_lm = primary_loss + secondary_loss

            simulated_annual_loss = lef * total_lm
            annual_losses.append(simulated_annual_loss)

        annual_losses.sort()

        expected_annual_loss = sum(annual_losses) / len(annual_losses)
        p10 = annual_losses[int(0.10 * len(annual_losses))]
        p50 = annual_losses[int(0.50 * len(annual_losses))]
        p90 = annual_losses[int(0.90 * len(annual_losses))]
        p95 = annual_losses[int(0.95 * len(annual_losses))]

        # Exceedance Curve (Probability of annual loss exceeding threshold)
        thresholds = [500000, 1000000, 2500000, 5000000, 10000000]
        exceedance_curve = []
        for thresh in thresholds:
            prob = sum(1 for l in annual_losses if l >= thresh) / len(annual_losses)
            exceedance_curve.append({
                "threshold_inr": thresh,
                "formatted_threshold": _format_inr(thresh),
                "probability": round(prob, 3),
            })

        avg_lef = ((tef_min + tef_max) / 2) * ((vuln_min + vuln_max) / 2)
        avg_mag = ((mag_min + mag_max) / 2) * crit_factor

        return {
            "expected_annual_loss_inr": round(expected_annual_loss, 2),
            "formatted_inr": _format_inr(expected_annual_loss),
            "loss_event_frequency": round(avg_lef, 3),
            "loss_magnitude_inr": round(avg_mag, 2),
            "primary_loss_inr": round(avg_mag * 0.55, 2),
            "secondary_loss_inr": round(avg_mag * 0.45, 2),
            "percentiles": {
                "p10_inr": round(p10, 2),
                "p50_median_inr": round(p50, 2),
                "p90_inr": round(p90, 2),
                "p95_var_inr": round(p95, 2),
            },
            "exceedance_curve": exceedance_curve,
            "simulations_count": iterations,
        }
