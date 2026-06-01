"""Live scan progress UI."""

from collections.abc import Iterator

import streamlit as st

from core.models import ScanProgress


def render_progress(progress_iter: Iterator[ScanProgress]) -> ScanProgress | None:
    """Consume the orchestrator's progress generator, render live updates.

    Returns the final ScanProgress event (which contains partial_findings).
    """
    st.markdown("### ⏳ Scan in Progress")
    progress_bar = st.progress(0)
    status_placeholder = st.empty()

    last_event: ScanProgress | None = None
    for event in progress_iter:
        last_event = event
        progress_bar.progress(min(event.percent, 100))
        status_placeholder.markdown(
            f"**{event.step.replace('_', ' ').title()}** — {event.message}"
        )

    return last_event
