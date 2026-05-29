"""Tests for core Pydantic models."""

from datetime import datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from core.models import (
    AuditLogEntry,
    Finding,
    SafetyResult,
    ScanResult,
    ScanStatus,
    ScanType,
    Severity,
)


def test_finding_basic_creation(sample_finding: Finding) -> None:
    """Verify a Finding is created with expected fields and defaults."""
    assert sample_finding.title == "Test BOLA finding"
    assert sample_finding.severity == Severity.HIGH
    assert sample_finding.confidence == 0.85
    assert isinstance(sample_finding.id, str)
    UUID(sample_finding.id)  # valid UUID format
    assert sample_finding.evidence == {
        "request": "GET /users/2",
        "response_code": 200,
    }
    assert sample_finding.remediation == "Add authorization check on resource ownership."
    assert isinstance(sample_finding.discovered_at, datetime)


def test_finding_confidence_validation() -> None:
    """Confidence above 1.0 must raise ValidationError."""
    with pytest.raises(ValidationError):
        Finding(
            title="Invalid",
            description="Too high",
            severity=Severity.LOW,
            confidence=1.5,
            category="TEST",
        )


def test_finding_confidence_negative() -> None:
    """Negative confidence must raise ValidationError."""
    with pytest.raises(ValidationError):
        Finding(
            title="Invalid",
            description="Negative",
            severity=Severity.LOW,
            confidence=-0.1,
            category="TEST",
        )


def test_scan_result_severity_counts() -> None:
    """severity_counts() must correctly aggregate findings by severity."""
    findings = [
        Finding(
            title="F1", description="D1", severity=Severity.LOW,
            confidence=0.5, category="C1",
        ),
        Finding(
            title="F2", description="D2", severity=Severity.LOW,
            confidence=0.6, category="C2",
        ),
        Finding(
            title="F3", description="D3", severity=Severity.HIGH,
            confidence=0.9, category="C3",
        ),
        Finding(
            title="F4", description="D4", severity=Severity.CRITICAL,
            confidence=0.95, category="C4",
        ),
    ]
    result = ScanResult(
        scan_type=ScanType.API,
        target="https://api.example.com",
        status=ScanStatus.COMPLETED,
        findings=findings,
    )
    counts = result.severity_counts()
    assert counts["low"] == 2
    assert counts["high"] == 1
    assert counts["critical"] == 1
    assert counts["info"] == 0
    assert counts["medium"] == 0


def test_scan_result_default_status_workflow(sample_scan_result: ScanResult) -> None:
    """Verify ScanResult generates a UUID and tracks status correctly."""
    assert isinstance(sample_scan_result.scan_id, str)
    UUID(sample_scan_result.scan_id)  # valid UUID format
    assert sample_scan_result.scan_type == ScanType.API
    assert sample_scan_result.status == ScanStatus.COMPLETED
    assert isinstance(sample_scan_result.started_at, datetime)
    assert isinstance(sample_scan_result.completed_at, datetime)
    assert len(sample_scan_result.findings) == 1


def test_audit_log_entry_defaults() -> None:
    """AuditLogEntry should default timestamp, user, and details."""
    entry = AuditLogEntry(event="scan_started")
    assert isinstance(entry.timestamp, datetime)
    assert entry.user == "local"
    assert entry.details == {}
    assert entry.target is None


def test_severity_enum_values() -> None:
    """Severity enum must contain exactly the expected five values."""
    assert Severity.INFO == "info"
    assert Severity.LOW == "low"
    assert Severity.MEDIUM == "medium"
    assert Severity.HIGH == "high"
    assert Severity.CRITICAL == "critical"
    assert len(Severity) == 5


def test_safety_result_construction() -> None:
    """Basic SafetyResult instantiation and field access."""
    result = SafetyResult(
        allowed=True,
        reason="Target passed safety checks",
        is_production=False,
        target="http://localhost:8080",
    )
    assert result.allowed is True
    assert result.reason == "Target passed safety checks"
    assert result.is_production is False
    assert result.target == "http://localhost:8080"
