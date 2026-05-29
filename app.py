"""SecureQA Orchestrator — Main Streamlit application.

This file is the ONLY entry point. All business logic lives in core/.
Tab modules in tabs/ are thin UI wrappers that call core/ functions.

To run: streamlit run app.py
"""

import streamlit as st

from config.settings import settings
from core.logging_config import configure_logging
from core.storage import init_db
from tabs.ai_fuzzing import render_ai_fuzzing_tab
from tabs.api_security import render_api_security_tab
from tabs.ui_security import render_ui_security_tab


def _get_version() -> str:
    """Read version from pyproject.toml, falling back to a hardcoded default."""
    try:
        import tomllib

        with open("pyproject.toml", "rb") as f:
            data = tomllib.load(f)
            return str(data["project"]["version"])
    except Exception:
        return "0.1.0"


def main() -> None:
    """Render the SecureQA Orchestrator Streamlit application."""
    configure_logging()
    init_db()

    st.set_page_config(
        page_title="SecureQA Orchestrator",
        page_icon="🛡️",
        layout="wide",
    )

    # Global header
    left, _center, right = st.columns([1, 2, 1])
    with left:
        st.markdown("**🛡️ SecureQA Orchestrator**")
    with right:
        env = settings.environment
        if env == "development":
            st.markdown("🟢 Development")
        elif env == "staging":
            st.markdown("🟡 Staging")
        elif env == "production":
            st.markdown("🔴 Production")

    # Production warning banner
    if settings.environment == "production":
        st.error(
            "⚠️ Production environment detected. All scans are blocked by safety guard."
        )

    # Tab layout
    api_tab, ui_tab, fuzz_tab = st.tabs(
        ["🌐 API Security", "🖥️ UI Security", "🤖 AI Fuzzing"]
    )
    with api_tab:
        render_api_security_tab()
    with ui_tab:
        render_ui_security_tab()
    with fuzz_tab:
        render_ai_fuzzing_tab()

    # Footer
    st.divider()
    version = _get_version()
    st.markdown(
        f"<div style='text-align: center; color: gray; font-size: 0.8em;'>"
        f"Version {version} | "
        f"<a href='https://github.com/Yusuf-Hridoy/secureqa-orchestrator'>GitHub</a> | "
        f"Phase 0 — Foundation"
        f"</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
