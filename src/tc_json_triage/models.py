"""Shared data models for tc-json-triage."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    def reduced(self, levels: int) -> Severity:
        """Return a severity reduced by the given number of levels."""
        new_rank = max(self.rank - levels, 0)
        for s in Severity:
            if s.rank == new_rank:
                return s
        return Severity.INFO


class FindingSource(str, Enum):
    SCA = "sca"
    SAST = "sast"
    SECRETS = "secrets"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ScanFinding(BaseModel):
    """A normalized security scan finding."""

    id: str
    source: FindingSource
    tool: str
    rule_id: str
    severity: Severity
    cwes: list[str] = Field(default_factory=list)
    description: str
    file: str | None = None
    start_line: int | None = None
    cve_id: str | None = None
    package_name: str | None = None
    secret_type: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class ParsedMitigation(BaseModel):
    """A parsed mitigation from the threat model."""

    id: str
    numeric_id: int
    content: str
    status: str


class ParsedThreat(BaseModel):
    """A parsed threat from the threat model."""

    id: str
    numeric_id: int
    statement: str
    status: str
    stride: list[str] = Field(default_factory=list)
    priority: str = ""
    impacted_assets: list[str] = Field(default_factory=list)
    impacted_goal: list[str] = Field(default_factory=list)
    threat_source: str = ""
    threat_action: str = ""
    threat_impact: str = ""
    is_mitigated: bool = False
    linked_mitigations: list[ParsedMitigation] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class ThreatModel(BaseModel):
    """A parsed threat model."""

    threats: list[ParsedThreat] = Field(default_factory=list)
    mitigations: list[ParsedMitigation] = Field(default_factory=list)
    mitigation_links: list[dict[str, str]] = Field(default_factory=list)
    assumption_links: list[dict[str, str]] = Field(default_factory=list)


class CorrelationResult(BaseModel):
    """Result of correlating a finding against the threat model."""

    finding: ScanFinding
    matched_threat: ParsedThreat | None = None
    matched_mitigations: list[ParsedMitigation] = Field(default_factory=list)
    confidence: Confidence = Confidence.NONE
    adjusted_severity: Severity
    original_severity: Severity
    reason: str = ""
    is_gap: bool = False
