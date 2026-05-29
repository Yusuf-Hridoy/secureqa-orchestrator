"""Markdown exporter — stub for Phase 0. Full implementation in Phase 1."""

from core.exporters.base import Exporter
from core.models import ScanResult


class MarkdownExporter(Exporter):
    """Exports scan results as Markdown reports."""

    name = "markdown"

    def export(self, result: ScanResult) -> str:
        """Return a placeholder Markdown report. Full impl in Phase 1."""
        return (
            f"# Scan Report — {result.scan_type.value.upper()}\n\n"
            f"**Status:** TODO — full implementation in Phase 1\n\n"
            f"- Scan ID: `{result.scan_id}`\n"
            f"- Target: `{result.target}`\n"
            f"- Status: `{result.status.value}`\n"
            f"- Findings: {len(result.findings)}\n"
        )
