"""CSV exporter — stub for Phase 0. Full implementation in Phase 1."""

import csv
import io

from core.exporters.base import Exporter
from core.models import ScanResult


class CSVExporter(Exporter):
    """Exports findings as CSV matrix."""

    name = "csv"

    def export(self, result: ScanResult) -> str:
        """Return a placeholder CSV. Full impl in Phase 1."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["scan_id", "target", "status", "findings_count"])
        writer.writerow([
            result.scan_id,
            result.target,
            result.status.value,
            len(result.findings),
        ])
        return buf.getvalue()
