"""Findings display + filters + download buttons."""

from collections import Counter

import streamlit as st

from core.api_security.ui.filters import filter_findings
from core.api_security.ui.formatters import (
    SEVERITY_ICONS,
    format_latency,
    format_severity_badge,
)
from core.exporters.csv_exporter import CSVExporter
from core.exporters.markdown_exporter import MarkdownExporter
from core.models import ScanResult, Severity


def render_findings(scan_result: ScanResult) -> None:
    """Render the findings section: summary, filters, table, downloads."""
    st.markdown("### 📊 Findings")

    if not scan_result.findings:
        st.success("✅ No findings detected. The target passed all automated checks.")
        _render_download_buttons(scan_result)
        return

    _render_severity_summary(scan_result)

    # Filters
    sev_filter, cat_filter, search = _render_filter_bar(scan_result)

    filtered = filter_findings(
        scan_result.findings,
        severities=sev_filter or None,
        categories=cat_filter or None,
        search_text=search or None,
    )

    st.caption(
        f"Showing {len(filtered)} of {len(scan_result.findings)} findings"
    )

    # Findings table (one expander per finding)
    for f in filtered:
        with st.expander(
            f"{SEVERITY_ICONS.get(f.severity, '⚪')} **{f.title}** "
            f"— `{f.category}`  ({f.confidence:.0%} confidence)",
            expanded=False,
        ):
            _render_finding_detail(f)

    _render_download_buttons(scan_result)


def _render_severity_summary(scan_result: ScanResult) -> None:
    """Top-of-section summary cards by severity."""
    sev_counts = Counter(f.severity for f in scan_result.findings)
    cols = st.columns(5)
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for col, sev in zip(cols, order, strict=False):
        with col:
            count = sev_counts.get(sev, 0)
            icon = SEVERITY_ICONS.get(sev, "⚪")
            st.metric(f"{icon} {sev.value.upper()}", count)


def _render_filter_bar(scan_result: ScanResult):
    """Returns (severity_set, category_set, search_text)."""
    cols = st.columns([2, 2, 3])
    with cols[0]:
        sev_choice = st.multiselect(
            "Severity",
            options=[s.value for s in Severity],
            default=[],
            key="filter_severity",
        )
    with cols[1]:
        cats = sorted({f.category for f in scan_result.findings})
        cat_choice = st.multiselect(
            "Category",
            options=cats,
            default=[],
            key="filter_category",
        )
    with cols[2]:
        search = st.text_input("Search (title / description)", key="filter_search")

    sev_set = {Severity(s) for s in sev_choice} if sev_choice else set()
    cat_set = set(cat_choice) if cat_choice else set()
    return sev_set, cat_set, search


def _render_finding_detail(finding) -> None:
    """Renders the expanded body of a single finding."""
    st.markdown(f"**Severity:** {format_severity_badge(finding.severity)}")
    st.markdown(f"**Category:** `{finding.category}`")
    st.markdown(f"**Confidence:** `{finding.confidence:.0%}`")

    if finding.description:
        st.markdown("**Description**")
        st.write(finding.description)

    evidence = finding.evidence or {}
    request = evidence.get("request", {})
    response = evidence.get("response", {})

    if request or response:
        st.markdown("**Evidence**")
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("*Request*")
            st.json({k: v for k, v in request.items() if v is not None})
        with col_b:
            st.markdown("*Response*")
            display_resp = {
                "http_status": response.get("http_status"),
                "latency": format_latency(response.get("latency_ms") or 0),
                "size_bytes": response.get("size_bytes"),
                "headers": response.get("headers"),
            }
            st.json({k: v for k, v in display_resp.items() if v is not None})

        body_excerpt = response.get("body_excerpt")
        if body_excerpt:
            st.markdown("*Response body (excerpt)*")
            st.code(body_excerpt, language="json")

    llm_verdict = evidence.get("llm_verdict")
    if llm_verdict:
        st.markdown("**LLM Analysis**")
        st.info(llm_verdict.get("explanation", ""))

    if finding.remediation:
        st.markdown("**Remediation**")
        st.success(finding.remediation)

    refs = evidence.get("references")
    if refs:
        st.markdown("**References**")
        for r in refs:
            st.caption(f"- {r}")


def _render_download_buttons(scan_result: ScanResult) -> None:
    """Render Markdown + CSV download buttons."""
    st.markdown("---")
    st.markdown("### 📥 Export")
    col1, col2 = st.columns(2)
    with col1:
        md = MarkdownExporter().export(scan_result)
        st.download_button(
            "📄 Download Markdown Report",
            data=md,
            file_name=f"scan-{scan_result.scan_id[:8]}.md",
            mime="text/markdown",
        )
    with col2:
        csv_data = CSVExporter().export(scan_result)
        st.download_button(
            "📊 Download CSV Matrix",
            data=csv_data,
            file_name=f"scan-{scan_result.scan_id[:8]}.csv",
            mime="text/csv",
        )
