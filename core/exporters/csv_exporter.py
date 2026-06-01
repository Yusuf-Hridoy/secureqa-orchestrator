"""CSV exporter — flat one-row-per-finding format for Excel / sprint reviews."""

import csv
import io

from core.exporters.base import Exporter
from core.models import ScanResult

CSV_COLUMNS = [
    "scan_id",
    "target",
    "scan_status",
    "finding_id",
    "category",
    "severity",
    "confidence",
    "title",
    "description",
    "request_method",
    "request_url",
    "http_status",
    "latency_ms",
    "response_size_bytes",
    "rule_finding_score",
    "rule_confidence",
    "remediation",
    "references",
    "discovered_at",
]


class CSVExporter(Exporter):
    """Exports findings as CSV — one row per finding."""

    name = "csv"

    def export(self, result: ScanResult) -> str:
        buf = io.StringIO(newline="")
        writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()

        if not result.findings:
            # Still emit a single row indicating "no findings" so an empty CSV doesn't break Excel
            writer.writerow({
                "scan_id": result.scan_id,
                "target": result.target,
                "scan_status": result.status.value,
                "finding_id": "",
                "category": "(no findings)",
                "severity": "",
                "confidence": "",
                "title": "Scan completed with no findings",
                "description": "",
                "request_method": "",
                "request_url": "",
                "http_status": "",
                "latency_ms": "",
                "response_size_bytes": "",
                "rule_finding_score": "",
                "rule_confidence": "",
                "remediation": "",
                "references": "",
                "discovered_at": "",
            })
            return buf.getvalue()

        for f in result.findings:
            evidence = f.evidence or {}
            request = evidence.get("request", {})
            response = evidence.get("response", {})
            rule = evidence.get("rule_outcome", {})
            refs = evidence.get("references") or []

            if not isinstance(request, dict):
                request = {}
            if not isinstance(response, dict):
                response = {}
            if not isinstance(rule, dict):
                rule = {}

            writer.writerow({
                "scan_id": result.scan_id,
                "target": result.target,
                "scan_status": result.status.value,
                "finding_id": f.id,
                "category": f.category,
                "severity": f.severity.value,
                "confidence": f"{f.confidence:.3f}",
                "title": f.title,
                "description": _flatten_text(f.description),
                "request_method": request.get("method", ""),
                "request_url": request.get("url") or request.get("path", ""),
                "http_status": response.get("http_status", ""),
                "latency_ms": response.get("latency_ms", ""),
                "response_size_bytes": response.get("size_bytes", ""),
                "rule_finding_score": rule.get("finding_score", ""),
                "rule_confidence": rule.get("rule_confidence", ""),
                "remediation": _flatten_text(f.remediation or ""),
                "references": " | ".join(refs),
                "discovered_at": f.discovered_at.isoformat() if f.discovered_at else "",
            })

        return buf.getvalue()


def _flatten_text(text: str) -> str:
    """Replace newlines with spaces so CSV stays one-row-per-finding."""
    if not text:
        return ""
    return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
