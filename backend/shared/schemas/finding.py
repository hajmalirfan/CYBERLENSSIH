"""SecuriX Unified Finding Schema.

Common data shape shared across all 6 scanner services, Kafka event bus,
Apache AGE knowledge graph, AI agent mesh, and the Backstage/SecuriX portal.
Supports both legacy fields (tool, file, line) and team Day 0 fields (source_tool, file_path, line_number).
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class FAIRExposure(BaseModel):
    """Quantitative risk breakdown in Indian Rupees (₹)."""

    loss_event_frequency: float = 0.1
    loss_magnitude_inr: float = 500000.0
    expected_annual_loss_inr: float = 50000.0
    primary_loss_inr: float = 30000.0
    secondary_loss_inr: float = 20000.0
    formatted_inr: str = "₹50,000"
    risk_level: str = "MODERATE"


class OPAVerdict(BaseModel):
    """Compliance verdict from OPA Rego policy evaluation."""

    regulation: str  # RBI, SEBI, ISO27001, NIST_CSF, DPDP
    control_id: str
    control_name: str
    status: str = "FAIL"  # PASS | FAIL | NOT_APPLICABLE
    rationale: Optional[str] = None


class Finding(BaseModel):
    """Normalized SecuriX finding shared by all 6 scanner services and core platform."""

    scan_id: str
    source_tool: Optional[str] = None
    tool: Optional[str] = None
    target: str

    rule_id: Optional[str] = None
    title: str
    description: Optional[str] = None

    severity: str = "info"  # critical, high, medium, low, info

    file_path: Optional[str] = None
    file: Optional[str] = None
    line_number: Optional[int] = None
    line: Optional[int] = None
    column: Optional[int] = None

    category: Optional[str] = "vulnerability"
    evidence: Optional[str] = None
    remediation: Optional[str] = None

    # Asset context
    asset_id: Optional[str] = None
    asset_type: Optional[str] = None  # repo, container_image, iac_source, web_endpoint, host, network

    # Vulnerability metadata
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: Optional[str] = "medium"

    # Agent Mesh: Quantification & Compliance
    fair_exposure: Optional[FAIRExposure] = None
    compliance_tags: List[str] = Field(default_factory=list)
    opa_verdicts: List[OPAVerdict] = Field(default_factory=list)

    # Verification status (analyst sign-off)
    verified: bool = False
    verified_by: Optional[str] = None
    verified_at: Optional[datetime] = None

    # Raw tool outputs and metadata
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Timestamps
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    timestamp: Optional[datetime] = None

    @model_validator(mode="before")
    @classmethod
    def reconcile_field_aliases(cls, data: Any) -> Any:
        """Harmonize tool/source_tool, file/file_path, line/line_number, timestamp/scanned_at."""
        if not isinstance(data, dict):
            return data

        d = dict(data)
        # Harmonize tool / source_tool
        t = d.get("tool") or d.get("source_tool") or "unknown"
        d["tool"] = t
        d["source_tool"] = t

        # Harmonize file / file_path
        f = d.get("file") or d.get("file_path")
        d["file"] = f
        d["file_path"] = f

        # Harmonize line / line_number
        l = d.get("line") if d.get("line") is not None else d.get("line_number")
        d["line"] = l
        d["line_number"] = l

        # Harmonize timestamp / scanned_at
        ts = d.get("timestamp") or d.get("scanned_at")
        if ts:
            d["timestamp"] = ts
            d["scanned_at"] = ts

        # Fallback asset_id if not explicitly provided
        if not d.get("asset_id"):
            d["asset_id"] = d.get("target")

        return d

    def to_kafka_dict(self) -> Dict[str, Any]:
        """Convert finding to JSON-safe dictionary for Kafka publication."""
        return self.model_dump(mode="json")

    def to_graph_node(self) -> Dict[str, Any]:
        """Extract properties for Knowledge Graph Finding node."""
        exposure_inr = self.fair_exposure.expected_annual_loss_inr if self.fair_exposure else 0.0
        return {
            "id": f"{self.tool}_{self.rule_id}_{self.scan_id[:8]}",
            "scan_id": self.scan_id,
            "tool": self.tool or self.source_tool,
            "target": self.target,
            "asset_id": self.asset_id or self.target,
            "rule_id": self.rule_id or "GENERIC",
            "title": self.title,
            "severity": self.severity.lower(),
            "description": self.description or "",
            "file": self.file or self.file_path or "",
            "line": self.line or self.line_number or 0,
            "category": self.category or "code",
            "expected_annual_loss_inr": exposure_inr,
            "verified": self.verified,
            "scanned_at": (self.scanned_at or datetime.now(timezone.utc)).isoformat(),
        }
