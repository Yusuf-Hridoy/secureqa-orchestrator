"""Input panel for the API Security tab.

Renders the file upload + target URL + auth context form.
"""

from dataclasses import dataclass

import streamlit as st

from core.api_security.execution.models import AuthContext


@dataclass
class InputPanelResult:
    """Output of the input panel: everything needed to start a scan."""
    spec_bytes: bytes | None
    spec_filename: str | None
    target_url: str
    auth_context: AuthContext
    scan_requested: bool


def render_input_panel() -> InputPanelResult:
    """Render the input panel and return user inputs."""
    st.markdown("### 🌐 Scan Configuration")

    # Spec upload
    uploaded = st.file_uploader(
        "Upload OpenAPI spec or Postman collection",
        type=["json", "yaml", "yml"],
        help="Supports OpenAPI 3.0, OpenAPI 3.1 (JSON/YAML), Postman Collection v2.1.",
        key="spec_upload",
    )

    spec_bytes = uploaded.read() if uploaded else None
    spec_filename = uploaded.name if uploaded else None

    # Target URL
    target_url = st.text_input(
        "Target base URL",
        value=st.session_state.get("target_url", "https://api.staging.example.com"),
        placeholder="https://api.staging.yourcompany.com",
        help="Staging or dev environments only. Production URLs are blocked.",
        key="target_url",
    )

    # Auth context (optional)
    auth_context = _render_auth_expander()

    # Scan trigger
    scan_requested = st.button(
        "🚀 Run Security Scan",
        type="primary",
        disabled=(spec_bytes is None or not target_url),
        key="scan_button",
    )

    return InputPanelResult(
        spec_bytes=spec_bytes,
        spec_filename=spec_filename,
        target_url=target_url,
        auth_context=auth_context,
        scan_requested=scan_requested,
    )


def _render_auth_expander() -> AuthContext:
    """Render the optional auth context form."""
    with st.expander("🔐 Auth Context (optional, for authenticated endpoints)", expanded=False):
        st.caption(
            "These tokens are used to test authenticated endpoints. "
            "Tests that require tokens you don't provide will be SKIPPED automatically."
        )

        tab_simple, tab_advanced = st.tabs(["Simple", "Advanced (multi-user)"])

        with tab_simple:
            bearer = st.text_input(
                "Bearer token",
                type="password",
                placeholder="eyJhbGc...",
                help="Pasted as-is into the Authorization: Bearer header.",
                key="auth_bearer",
            )

        with tab_advanced:
            st.caption(
                "For BOLA cross-tenant tests, provide two separate user tokens "
                "and a resource ID that belongs to user B."
            )
            st.text_input("User A token", type="password", key="auth_user_a")
            st.text_input("User B token", type="password", key="auth_user_b")
            st.text_input(
                "User B resource ID",
                placeholder="42",
                help="A resource ID (e.g., /users/{id}) that belongs to user B.",
                key="auth_user_b_res",
            )
            st.text_input(
                "Admin token (optional, for function-level auth tests)",
                type="password",
                key="auth_admin",
            )
            st.text_input(
                "Regular user token (for FLA tests)",
                type="password",
                key="auth_regular",
            )

    return AuthContext(
        bearer_token=bearer or None,
        user_a_token=st.session_state.get("auth_user_a") or None,
        user_b_token=st.session_state.get("auth_user_b") or None,
        user_b_resource_id=st.session_state.get("auth_user_b_res") or None,
        admin_user_token=st.session_state.get("auth_admin") or None,
        regular_user_token=st.session_state.get("auth_regular") or None,
    )
