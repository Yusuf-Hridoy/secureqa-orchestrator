"""Tests for the SQLite storage layer."""

import pytest
from sqlalchemy import select

from core.models import (
    AuditLogEntry,
    ScanResult,
    ScanStatus,
    ScanType,
)
from core.storage import (
    AuditRecord,
    get_scan,
    get_session,
    list_scans,
    log_audit,
    save_scan,
)


@pytest.fixture
def patched_engine(in_memory_engine, monkeypatch):
    """Route all storage operations to the in-memory SQLite engine."""
    monkeypatch.setattr("core.storage.get_engine", lambda: in_memory_engine)
    yield in_memory_engine


def test_save_and_load_scan(sample_scan_result, patched_engine) -> None:
    """Round-trip a ScanResult through save → get."""
    save_scan(sample_scan_result)
    loaded = get_scan(sample_scan_result.scan_id)
    assert loaded is not None
    assert loaded.scan_id == sample_scan_result.scan_id
    assert loaded.target == sample_scan_result.target
    assert loaded.scan_type == sample_scan_result.scan_type


def test_get_nonexistent_scan_returns_none(patched_engine) -> None:
    """Loading an unknown scan_id must return None."""
    result = get_scan("does-not-exist")
    assert result is None


def test_list_scans_filters_by_type(patched_engine) -> None:
    """list_scans(scan_type=...) should return only matching scans."""
    scan1 = ScanResult(
        scan_type=ScanType.API, target="t1", status=ScanStatus.COMPLETED
    )
    scan2 = ScanResult(
        scan_type=ScanType.API, target="t2", status=ScanStatus.COMPLETED
    )
    scan3 = ScanResult(
        scan_type=ScanType.UI, target="t3", status=ScanStatus.COMPLETED
    )
    save_scan(scan1)
    save_scan(scan2)
    save_scan(scan3)
    api_scans = list_scans(scan_type="api")
    assert len(api_scans) == 2
    assert all(s.scan_type == ScanType.API for s in api_scans)


def test_list_scans_respects_limit(patched_engine) -> None:
    """list_scans(limit=...) must not exceed the requested count."""
    for i in range(5):
        scan = ScanResult(
            scan_type=ScanType.API,
            target=f"t{i}",
            status=ScanStatus.COMPLETED,
        )
        save_scan(scan)
    results = list_scans(limit=2)
    assert len(results) == 2


def test_log_audit_appends_entry(patched_engine) -> None:
    """log_audit should persist entries to the audit_log table."""
    log_audit(AuditLogEntry(event="e1", target="t1"))
    log_audit(AuditLogEntry(event="e2", target="t2"))
    with get_session() as session:
        entries = session.scalars(select(AuditRecord)).all()
        assert len(entries) == 2
        events = {e.event for e in entries}
        assert events == {"e1", "e2"}


def test_save_scan_preserves_findings(sample_scan_result, patched_engine) -> None:
    """A ScanResult with findings must reload with findings intact."""
    save_scan(sample_scan_result)
    loaded = get_scan(sample_scan_result.scan_id)
    assert loaded is not None
    assert len(loaded.findings) == len(sample_scan_result.findings)
    assert loaded.findings[0].title == sample_scan_result.findings[0].title
    assert loaded.findings[0].severity == sample_scan_result.findings[0].severity
