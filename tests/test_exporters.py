"""Tests for scan result exporters."""

from core.exporters import ClickUpExporter, CSVExporter, Exporter, MarkdownExporter


def test_markdown_exporter_returns_string(sample_scan_result) -> None:
    """MarkdownExporter must return a string containing scan metadata."""
    exporter = MarkdownExporter()
    result = exporter.export(sample_scan_result)
    assert isinstance(result, str)
    assert sample_scan_result.scan_id in result
    assert sample_scan_result.target in result


def test_csv_exporter_returns_csv_string(sample_scan_result) -> None:
    """CSVExporter must return a header row plus a data row."""
    exporter = CSVExporter()
    result = exporter.export(sample_scan_result)
    assert isinstance(result, str)
    lines = result.strip().splitlines()
    assert len(lines) == 2
    assert "scan_id" in lines[0]
    assert sample_scan_result.scan_id in lines[1]


def test_clickup_exporter_returns_dict(sample_scan_result) -> None:
    """ClickUpExporter must return a dict with the expected keys."""
    exporter = ClickUpExporter()
    result = exporter.export(sample_scan_result)
    assert isinstance(result, dict)
    assert "name" in result
    assert "description" in result
    assert "status" in result
    assert "tags" in result
    assert sample_scan_result.scan_id[:8] in result["name"]


def test_all_exporters_implement_base() -> None:
    """Every concrete exporter must be an instance of the Exporter ABC."""
    assert isinstance(MarkdownExporter(), Exporter)
    assert isinstance(CSVExporter(), Exporter)
    assert isinstance(ClickUpExporter(), Exporter)
