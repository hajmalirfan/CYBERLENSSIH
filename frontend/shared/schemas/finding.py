"""SecuriX Unified Finding & Platform Schemas (Frontend fallback mirror).

Common data shape shared across all scanner services, Kafka event bus,
Apache AGE knowledge graph, AI agent mesh, and the portal.
Section 3 of SecuriX Implementation Guide.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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
    """Normalized SecuriX finding matching Section 3.1 of guide and platform needs."""

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = "generic"
    tier: int = 1
    tenant_id: str = "default"
    repo_id: Optional[str] = None
    asset_id: Optional[str] = None
    commit_sha: Optional[str] = None
    rule_id: str = "GENERIC"
    severity: Severity = Severity.MEDIUM
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    description: str = ""
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    scan_id: Optional[str] = None
    source_tool: Optional[str] = None
    tool: Optional[str] = None
    target: Optional[str] = None
    title: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    category: Optional[str] = "vulnerability"
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    asset_type: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: Optional[str] = "medium"
    status: str = "open"

    fair_exposure: Optional[FAIRExposure] = None
    compliance_tags: List[str] = Field(default_factory=list)
    opa_verdicts: List[OPAVerdict] = Field(default_factory=list)

    verified: bool = False
    verified_by: Optional[str] = None
    verified_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    scanned_at: Optional[datetime] = None
    timestamp: Optional[datetime] = None

    @model_validator(mode="before")
    @classmethod
    def reconcile_field_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        d = dict(data)

        fid = d.get("finding_id") or d.get("id") or d.get("scan_id")
        if not fid:
            fid = str(uuid4())
        d["finding_id"] = str(fid)
        if not d.get("scan_id"):
            d["scan_id"] = str(fid)

        src = d.get("source") or d.get("source_tool") or d.get("tool") or "unknown"
        d["source"] = src
        d["source_tool"] = src
        d["tool"] = src

        f = d.get("file_path") or d.get("file")
        d["file"] = f
        d["file_path"] = f
        l = d.get("line_number") if d.get("line_number") is not None else d.get("line")
        d["line"] = l
        d["line_number"] = l

        tgt = d.get("target") or d.get("asset_id") or d.get("repo_id") or "default_target"
        d["target"] = tgt
        if not d.get("asset_id"):
            d["asset_id"] = tgt

        desc = d.get("description") or d.get("title") or d.get("rule_id") or "Security finding"
        d["description"] = desc
        if not d.get("title"):
            d["title"] = desc[:120]

        sev_val = str(d.get("severity", "medium")).lower()
        try:
            d["severity"] = Severity(sev_val)
        except Exception:
            d["severity"] = Severity.MEDIUM

        now = datetime.now(timezone.utc)
        ts = d.get("detected_at") or d.get("scanned_at") or d.get("timestamp") or now
        d["detected_at"] = ts
        d["scanned_at"] = ts
        d["timestamp"] = ts

        return d

    def to_kafka_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class Alert(BaseModel):
    finding_id: str
    tenant_id: str = "default"
    asset: str
    title: str
    severity: str
    eal_inr: float
    rank: int
    verdicts: Dict[str, str] = Field(default_factory=dict)
    exploitable: bool = False
    evidence_url: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RiskState(BaseModel):
    finding_id: str
    tenant_id: str = "default"
    asset_id: Optional[str] = None
    title: str = ""
    eal_inr: float = 0.0
    p90_loss_inr: float = 0.0
    rank: int = 1
    verdicts: Dict[str, str] = Field(default_factory=dict)
    evidence_url: str = ""
    status: str = "open"
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanJob(BaseModel):
    job_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str = "default"
    repo_id: str
    mode: str = "incremental"
    commit_sha: Optional[str] = None
    status: str = "queued"
    tools_run: List[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
