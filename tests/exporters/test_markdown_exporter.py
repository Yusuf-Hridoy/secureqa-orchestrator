"""Tests for the real MarkdownExporter."""

from datetime import datetime

from core.exporters.markdown_exporter import MarkdownExporter
from core.models import Finding, ScanResult, ScanStatus, ScanType, Severity


def _f(title="Issue", severity=Severity.HIGH, category="API1_BOLA"):
    return Finding(
        title=title,
        description="A finding description",
        severity=severity,
        confidence=0.8,
        category=category,
        evidence={
            "request": {"method": "GET", "url": "https://api.staging.example.com/users/1"},
            "response": {"http_status": 200, "latency_ms": 120.5, "size_bytes": 1024},
            "rule_outcome": {"finding_score": 0.9, "rule_confidence": 0.85},
        },
        remediation="Add authorization check.",
    )


def _scan(findings=None, status=ScanStatus.COMPLETED):
    return ScanResult(
        scan_type=ScanType.API,
        target="https://api.staging.example.com",
        status=status,
        started_at=datetime(2026, 1, 1, 10, 0, 0),
        completed_at=datetime(2026, 1, 1, 10, 1, 30),
        findings=findings or [],
        summary={
            "total_findings": len(findings or []),
            "total_tests_planned": 50,
            "total_tests_executed": 45,
            "findings_by_severity": {
                "critical": sum(1 for f in (findings or []) if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in (findings or []) if f.severity == Severity.HIGH),
                "medium": sum(1 for f in (findings or []) if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in (findings or []) if f.severity == Severity.LOW),
                "info": sum(1 for f in (findings or []) if f.severity == Severity.INFO),
            },
            "skipped_count": 5,
            "error_count": 0,
        },
        metadata={"config": {"target_base_url": "https://api.staging.example.com", "concurrency": 5}},
    )


def test_header_contains_target_and_scan_id():
    out = MarkdownExporter().export(_scan())
    assert "https://api.staging.example.com" in out
    assert "Scan ID" in out


def test_no_findings_section_renders_clean_summary():
    out = MarkdownExporter().export(_scan(findings=[]))
    assert "No security findings" in out


def test_critical_findings_get_priority_messaging():
    out = MarkdownExporter().export(_scan(findings=[_f(severity=Severity.CRITICAL)]))
    assert "critical" in out.lower()
    assert "P0" in out


def test_findings_grouped_by_severity():
    findings = [
        _f(title="Crit", severity=Severity.CRITICAL),
        _f(title="High1", severity=Severity.HIGH),
        _f(title="High2", severity=Severity.HIGH),
        _f(title="Low", severity=Severity.LOW),
    ]
    out = MarkdownExporter().export(_scan(findings=findings))
    assert "### 🔴 CRITICAL (1)" in out
    assert "### 🟠 HIGH (2)" in out
    assert "### 🟢 LOW (1)" in out


def test_evidence_table_included():
    out = MarkdownExporter().export(_scan(findings=[_f()]))
    assert "Request" in out
    assert "HTTP Status" in out
    assert "200" in out


def test_remediation_section_included():
    out = MarkdownExporter().export(_scan(findings=[_f()]))
    assert "Remediation" in out
    assert "Add authorization check" in out


def test_blocked_scan_renders_blocked_message():
    scan = _scan(status=ScanStatus.BLOCKED)
    scan.summary = {"blocked_reason": "Production URL"}
    out = MarkdownExporter().export(scan)
    assert "Scan Blocked" in out
    assert "Production URL" in out


def test_appendix_contains_config():
    out = MarkdownExporter().export(_scan(findings=[_f()]))
    assert "Appendix" in out
    assert "concurrency" in out


def test_severity_breakdown_table_renders():
    out = MarkdownExporter().export(_scan(findings=[_f(severity=Severity.HIGH)]))
    assert "Critical" in out
    assert "High" in out
    assert "Total" in out
