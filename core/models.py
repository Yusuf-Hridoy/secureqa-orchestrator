"""Shared Pydantic models for SecureQA Orchestrator."""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(str, Enum):
    """Lifecycle states for a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"  # Blocked by safety layer


class ScanType(str, Enum):
    """Type of scan (matches tab names)."""

    API = "api"
    UI = "ui"
    FUZZING = "fuzzing"


class Finding(BaseModel):
    """A single security finding from a scan."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    category: str  # e.g., "OWASP_API_01_BOLA"
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class ScanProgress(BaseModel):
    """Progress update from a running scan (used by generators)."""

    step: str  # "parsing", "executing", "analyzing", "complete"
    percent: int = Field(ge=0, le=100)
    message: str
    partial_findings: list[Finding] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Final result of a scan."""

    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    scan_type: ScanType
    target: str
    status: ScanStatus
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        """Return count of findings grouped by severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


class SafetyResult(BaseModel):
    """Result of a safety check on a target URL."""

    allowed: bool
    reason: str
    is_production: bool
    target: str


class AuditLogEntry(BaseModel):
    """An entry in the audit log (security/compliance trail)."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event: str  # "scan_started", "prod_blocked", "export_clicked", etc.
    target: str | None = None
    user: str = "local"
    details: dict[str, Any] = Field(default_factory=dict)
