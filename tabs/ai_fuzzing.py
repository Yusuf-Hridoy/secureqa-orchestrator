"""AI Fuzzing & Input Agent tab — Phase 3 placeholder."""

import streamlit as st


def render_ai_fuzzing_tab() -> None:
    """Render the AI Fuzzing & Input Agent tab. Phase 3 implementation pending."""
    st.header("🤖 AI Fuzzing & Input Agent")
    st.info(
        "**Phase 3 — Coming Soon**\n\n"
        "This tab will provide LLM-driven fuzzing and input testing:\n"
        "- AI-generated payloads (boundary, malformed, safe SQLi/XSS patterns)\n"
        "- Real-time payload → response → classification matrix\n"
        "- Severity scoring with manual triage UI\n"
        "- Error verbosity / information disclosure detection"
    )
    st.caption("See README.md for full roadmap.")
