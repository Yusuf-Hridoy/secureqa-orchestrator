"""API Security Validator tab — Phase 1 placeholder."""

import streamlit as st


def render_api_security_tab() -> None:
    """Render the API Security Validator tab. Phase 1 implementation pending."""
    st.header("🌐 API Security Validator")
    st.info(
        "**Phase 1 — Coming Soon**\n\n"
        "This tab will provide automated OWASP API Security Top 10 testing:\n"
        "- Upload OpenAPI spec (YAML/JSON)\n"
        "- Auto-generate security tests (BOLA, broken auth, excessive data exposure, etc.)\n"
        "- Execute via Newman/Postman runner\n"
        "- Export findings as Markdown, CSV, or create a ClickUp ticket"
    )
    st.caption("See README.md for full roadmap.")
