"""Tests for the real CSVExporter."""

import csv
import io
from datetime import datetime

from core.exporters.csv_exporter import CSV_COLUMNS, CSVExporter
from core.models import Finding, ScanResult, ScanStatus, ScanType, Severity


def _f(severity=Severity.HIGH):
    return Finding(
        title="Test finding",
        description="Multi-line\ndescription",
        severity=severity,
        confidence=0.8,
        category="API1_BOLA",
        evidence={
            "request": {"method": "GET", "url": "https://api.staging.example.com/x"},
            "response": {"http_status": 200, "latency_ms": 120, "size_bytes": 1024},
            "rule_outcome": {"finding_score": 0.9, "rule_confidence": 0.85},
        },
        remediation="Fix it.\nAlso fix this.",
    )


def _scan(findings=None):
    return ScanResult(
        scan_type=ScanType.API,
        target="https://api.staging.example.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, 10, 0, 0),
        completed_at=datetime(2026, 1, 1, 10, 0, 30),
        findings=findings or [],
    )


def _parse(csv_text):
    return list(csv.DictReader(io.StringIO(csv_text)))


def test_header_has_all_columns():
    out = CSVExporter().export(_scan(findings=[_f()]))
    rows = _parse(out)
    assert set(rows[0].keys()) == set(CSV_COLUMNS)


def test_one_row_per_finding():
    out = CSVExporter().export(_scan(findings=[_f(), _f(severity=Severity.LOW)]))
    rows = _parse(out)
    assert len(rows) == 2


def test_empty_findings_emits_placeholder_row():
    out = CSVExporter().export(_scan(findings=[]))
    rows = _parse(out)
    assert len(rows) == 1
    assert rows[0]["category"] == "(no findings)"


def test_newlines_in_description_flattened():
    out = CSVExporter().export(_scan(findings=[_f()]))
    rows = _parse(out)
    # description should not contain raw newlines (they'd break CSV row count)
    assert "\n" not in rows[0]["description"]
    assert "Multi-line" in rows[0]["description"]


def test_severity_serialized_as_string():
    out = CSVExporter().export(_scan(findings=[_f(severity=Severity.CRITICAL)]))
    rows = _parse(out)
    assert rows[0]["severity"] == "critical"


def test_confidence_formatted():
    out = CSVExporter().export(_scan(findings=[_f()]))
    rows = _parse(out)
    assert rows[0]["confidence"] == "0.800"


def test_response_fields_extracted():
    out = CSVExporter().export(_scan(findings=[_f()]))
    rows = _parse(out)
    assert rows[0]["http_status"] == "200"
    assert rows[0]["latency_ms"] == "120"
    assert rows[0]["response_size_bytes"] == "1024"


def test_references_joined_with_pipe():
    f = _f()
    f.evidence["references"] = ["CWE-639", "OWASP API1:2023"]
    out = CSVExporter().export(_scan(findings=[f]))
    rows = _parse(out)
    assert "CWE-639" in rows[0]["references"]
    assert " | " in rows[0]["references"]
