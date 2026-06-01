"""Settings expander for the API Security tab.

Renders a collapsible 'Advanced Settings' section. Mutates the ScanConfig
returned by reading current values from st.session_state.
"""

import streamlit as st

from core.api_security.execution.models import ScanConfig


def render_settings_expander(default_target: str = "") -> ScanConfig:
    """Render advanced settings and return a ScanConfig.

    Side effects:
      - Writes user choices into st.session_state.
    """
    with st.expander("⚙️ Advanced Settings", expanded=False):
        st.markdown("##### Execution")

        col1, col2 = st.columns(2)
        with col1:
            concurrency = st.slider(
                "Concurrent requests",
                min_value=1,
                max_value=20,
                value=st.session_state.get("cfg_concurrency", 5),
                step=1,
                help="Higher = faster scan, but may overwhelm small staging APIs.",
                key="cfg_concurrency",
            )
        with col2:
            request_timeout = st.slider(
                "Request timeout (seconds)",
                min_value=1.0,
                max_value=60.0,
                value=st.session_state.get("cfg_request_timeout", 10.0),
                step=1.0,
                key="cfg_request_timeout",
            )

        overall_timeout = st.slider(
            "Overall scan timeout (minutes)",
            min_value=1,
            max_value=30,
            value=st.session_state.get("cfg_overall_timeout_min", 10),
            step=1,
            help="Scan will abort with partial results after this many minutes.",
            key="cfg_overall_timeout_min",
        )

        st.markdown("##### LLM-Assisted Analysis")
        use_llm_classification = st.checkbox(
            "✨ Use Gemini to tie-break ambiguous findings",
            value=st.session_state.get("cfg_use_llm_class", True),
            help="When rule-based confidence is low (< 0.5), Gemini reviews the response.",
            key="cfg_use_llm_class",
        )
        use_llm_explanations = st.checkbox(
            "📝 Generate human-readable explanations for findings",
            value=st.session_state.get("cfg_use_llm_explain", True),
            help="Each finding gets an LLM-generated summary, details, and remediation.",
            key="cfg_use_llm_explain",
        )

        st.markdown("##### Safety")
        allow_destructive = st.checkbox(
            "⚠️ Allow destructive methods (POST/PUT/PATCH/DELETE)",
            value=st.session_state.get("cfg_allow_destructive", False),
            help=(
                "Enable ONLY for staging environments where you control the data. "
                "Destructive ops may modify or delete data on the target."
            ),
            key="cfg_allow_destructive",
        )
        if allow_destructive:
            st.warning(
                "Destructive methods enabled. Ensure your target is a "
                "non-production staging environment with restorable data."
            )

    return ScanConfig(
        target_base_url=default_target or "https://api.staging.example.com",
        concurrency=concurrency,
        request_timeout_seconds=request_timeout,
        overall_timeout_seconds=overall_timeout * 60,
        use_llm_classification=use_llm_classification,
        use_llm_explanations=use_llm_explanations,
        allow_destructive_methods=allow_destructive,
    )
