"""Recent scans sidebar — last 10 scans from SQLite history."""

import streamlit as st

from core.api_security.ui.formatters import SEVERITY_ICONS
from core.models import ScanResult, ScanType, Severity
from core.storage import list_scans


def render_history_sidebar() -> ScanResult | None:
    """Render the recent-scans sidebar. Returns a ScanResult if user clicks one, else None.

    Stores selection in st.session_state.selected_history_scan_id.
    """
    with st.sidebar:
        st.markdown("### 🕘 Recent Scans")
        try:
            scans = list_scans(limit=10, scan_type=ScanType.API.value)
        except Exception:
            scans = []

        if not scans:
            st.caption("_No previous scans yet._")
            return None

        selected: ScanResult | None = None
        for scan in scans:
            sev_counts = scan.severity_counts() if hasattr(scan, "severity_counts") else {}
            highest = _highest_severity_icon(sev_counts)
            label = (
                f"{highest} {scan.target[:30]}... "
                f"({sum(sev_counts.values())} findings)"
                if hasattr(scan, "severity_counts")
                else f"{scan.target[:30]}... ({len(scan.findings)} findings)"
            )

            time_str = scan.started_at.strftime("%m-%d %H:%M") if scan.started_at else ""

            if st.button(
                f"{label}\n_{time_str}_",
                key=f"history_{scan.scan_id}",
                use_container_width=True,
            ):
                selected = scan

        return selected


def _highest_severity_icon(sev_counts: dict) -> str:
    """Return icon for the highest severity present."""
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if sev_counts.get(sev.value, 0) > 0:
            return SEVERITY_ICONS.get(sev, "⚪")
    return "⚪"
