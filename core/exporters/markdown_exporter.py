"""Markdown exporter — produces professional finding reports."""

from datetime import datetime

from core.api_security.ui.formatters import SEVERITY_ICONS, format_latency
from core.exporters.base import Exporter
from core.models import Finding, ScanResult, Severity

# Severity display order for sections
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class MarkdownExporter(Exporter):
    """Generates a complete Markdown report from a ScanResult."""

    name = "markdown"

    def export(self, result: ScanResult) -> str:
        sections = [
            self._header(result),
            self._executive_summary(result),
            self._findings_by_severity(result),
            self._appendix(result),
        ]
        return "\n\n".join(s for s in sections if s)

    # ---------- Sections ----------

    def _header(self, result: ScanResult) -> str:
        completed = (
            result.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if result.completed_at else "incomplete"
        )
        duration_str = ""
        if result.completed_at and result.started_at:
            duration_s = (result.completed_at - result.started_at).total_seconds()
            duration_str = f" ({duration_s:.1f}s)"

        return (
            f"# SecureQA Orchestrator — API Security Report\n\n"
            f"**Target:** `{result.target}`  \n"
            f"**Scan ID:** `{result.scan_id}`  \n"
            f"**Started:** {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  \n"
            f"**Completed:** {completed}{duration_str}  \n"
            f"**Status:** `{result.status.value}`"
        )

    def _executive_summary(self, result: ScanResult) -> str:
        if result.status.value == "blocked":
            return (
                "## ⚠️ Scan Blocked\n\n"
                f"This scan was blocked by the safety guard.  \n"
                f"**Reason:** {result.summary.get('blocked_reason', 'unspecified')}"
            )

        summary = result.summary or {}
        sev_counts = summary.get("findings_by_severity", {})
        total = summary.get("total_findings", len(result.findings))

        if total == 0:
            return (
                "## 🛡️ Executive Summary\n\n"
                "No security findings were detected by automated tests in this scan. "
                "This does not guarantee the API is secure — manual review and additional "
                "tooling are still recommended for production-grade assurance."
            )

        # Build summary line
        critical = sev_counts.get("critical", 0)
        high = sev_counts.get("high", 0)
        medium = sev_counts.get("medium", 0)
        low = sev_counts.get("low", 0)
        info = sev_counts.get("info", 0)

        # Risk level paragraph
        if critical > 0:
            risk = (
                f"**This scan identified {critical} critical-severity issue(s).** "
                "Critical findings represent confirmed authentication bypasses, "
                "data exposure, or remote code execution risks. These should be "
                "treated as P0 — fix before next deploy."
            )
        elif high > 0:
            risk = (
                f"**This scan identified {high} high-severity issue(s).** "
                "High-severity findings should be remediated in the current sprint."
            )
        elif medium > 0:
            risk = (
                "This scan identified medium-severity issues. "
                "These are best practices to improve overall security posture."
            )
        else:
            risk = (
                "This scan identified only low-severity / informational issues. "
                "Consider these during the next security hardening pass."
            )

        return (
            "## Executive Summary\n\n"
            f"{risk}\n\n"
            f"### Findings Breakdown\n\n"
            f"| Severity | Count |\n"
            f"| --- | --- |\n"
            f"| 🔴 Critical | {critical} |\n"
            f"| 🟠 High | {high} |\n"
            f"| 🟡 Medium | {medium} |\n"
            f"| 🟢 Low | {low} |\n"
            f"| ⚪ Info | {info} |\n"
            f"| **Total** | **{total}** |\n\n"
            f"### Scan Statistics\n\n"
            f"- Tests planned: {summary.get('total_tests_planned', 'unknown')}\n"
            f"- Tests executed: {summary.get('total_tests_executed', 'unknown')}\n"
            f"- Tests skipped (missing auth context, destructive, etc.): "
            f"{summary.get('skipped_count', 0)}\n"
            f"- Network errors / timeouts: {summary.get('error_count', 0)}"
        )

    def _findings_by_severity(self, result: ScanResult) -> str:
        if not result.findings:
            return ""

        # Group findings by severity
        by_severity: dict[Severity, list[Finding]] = {sev: [] for sev in SEVERITY_ORDER}
        for f in result.findings:
            by_severity[f.severity].append(f)

        sections = ["## Findings"]
        for severity in SEVERITY_ORDER:
            findings = by_severity[severity]
            if not findings:
                continue
            icon = SEVERITY_ICONS.get(severity, "⚪")
            sections.append(f"### {icon} {severity.value.upper()} ({len(findings)})\n")
            for i, finding in enumerate(findings, 1):
                sections.append(self._format_finding(i, finding))

        return "\n\n".join(sections)

    def _format_finding(self, index: int, finding: Finding) -> str:
        evidence = finding.evidence or {}
        request = evidence.get("request", {})
        response = evidence.get("response", {})
        rule_outcome = evidence.get("rule_outcome", {})

        # Normalize to dicts for safety
        if not isinstance(request, dict):
            request = {}
        if not isinstance(response, dict):
            response = {}
        if not isinstance(rule_outcome, dict):
            rule_outcome = {}

        # Header
        parts = [
            f"#### {index}. {finding.title}\n",
            f"**Category:** `{finding.category}`  \n"
            f"**Severity:** `{finding.severity.value}`  \n"
            f"**Confidence:** {finding.confidence:.0%}",
        ]

        # Description
        if finding.description:
            parts.append(f"\n**Description:**\n\n{finding.description}")

        # Evidence
        if request or response:
            parts.append("\n**Evidence:**\n")
            ev_table = ["| Field | Value |", "| --- | --- |"]
            if request:
                ev_table.append(
                    f"| Request | `{request.get('method', '?')} "
                    f"{request.get('url', request.get('path', '?'))}` |"
                )
            if response:
                ev_table.append(f"| HTTP Status | `{response.get('http_status', '?')}` |")
                latency = response.get("latency_ms")
                if latency is not None:
                    ev_table.append(f"| Latency | {format_latency(latency)} |")
                size = response.get("size_bytes")
                if size is not None:
                    ev_table.append(f"| Response Size | {size:,} bytes |")
            parts.append("\n".join(ev_table))

            body_excerpt = response.get("body_excerpt")
            if body_excerpt:
                parts.append("\n**Response body (excerpt):**\n")
                parts.append("```\n" + body_excerpt + "\n```")

        # Rule details
        if rule_outcome:
            score = rule_outcome.get("finding_score")
            conf = rule_outcome.get("rule_confidence")
            if score is not None and conf is not None:
                parts.append(
                    f"\n*Rule-based: score={score:.2f}, confidence={conf:.2f}*"
                )

        # LLM verdict
        llm_verdict = evidence.get("llm_verdict")
        if llm_verdict:
            parts.append(
                f"\n**LLM Analysis:** "
                f"_{llm_verdict.get('explanation', '(no explanation)')}_"
            )

        # Remediation
        if finding.remediation:
            parts.append(f"\n**Remediation:**\n\n{finding.remediation}")

        # References
        refs = evidence.get("references") or []
        if refs:
            parts.append("\n**References:**\n")
            for ref in refs:
                parts.append(f"- {ref}")

        return "\n".join(parts)

    def _appendix(self, result: ScanResult) -> str:
        meta = result.metadata or {}
        config = meta.get("config", {})
        if not config:
            return ""

        return (
            "## Appendix: Scan Configuration\n\n"
            "```\n"
            + "\n".join(f"{k}: {v}" for k, v in config.items() if k != "extra_headers")
            + "\n```\n\n"
            "---\n\n"
            f"_Generated by SecureQA Orchestrator at "
            f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}._"
        )
