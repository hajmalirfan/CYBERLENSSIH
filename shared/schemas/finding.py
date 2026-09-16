from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """Normalized SecuriX finding shared by all 6 scanner services."""

    scan_id: str
    tool: str
    target: str

    rule_id: Optional[str] = None
    title: str
    description: Optional[str] = None

    severity: str = "info"

    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None

    category: Optional[str] = None

    evidence: Optional[str] = None
    remediation: Optional[str] = None

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
