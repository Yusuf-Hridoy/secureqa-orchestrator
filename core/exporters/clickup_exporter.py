"""ClickUp exporter — stub for Phase 0. Real API integration in Phase 1."""

from core.exporters.base import Exporter
from core.models import ScanResult


class ClickUpExporter(Exporter):
    """Stub: returns a dict representing what would be sent to ClickUp."""

    name = "clickup"

    def export(self, result: ScanResult) -> dict:
        """Return a stub payload. Full ClickUp API call in Phase 1."""
        return {
            "name": f"[{result.scan_type.value.upper()}] Scan {result.scan_id[:8]} — {result.target}",
            "description": f"TODO: Full ClickUp integration in Phase 1.\nFindings: {len(result.findings)}",
            "status": "to do",
            "priority": 3,
            "tags": ["security", "automated-scan", result.scan_type.value],
        }
