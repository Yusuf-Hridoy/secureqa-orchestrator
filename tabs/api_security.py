"""API Security Validator tab — full Phase 1D implementation."""

import streamlit as st

from core.api_security import parse_spec
from core.api_security.exceptions import (
    APISecurityError,
    SpecParseError,
    UnsupportedSpecError,
)
from core.api_security.execution.orchestrator import ScanOrchestrator
from core.models import ScanResult
from tabs.api_security_components.findings_section import render_findings
from tabs.api_security_components.history_sidebar import render_history_sidebar
from tabs.api_security_components.input_panel import render_input_panel
from tabs.api_security_components.progress_section import render_progress
from tabs.api_security_components.settings_expander import render_settings_expander

SESSION_LAST_SCAN = "api_sec_last_scan"


def render_api_security_tab() -> None:
    """Top-level renderer for the API Security tab."""
    st.header("🌐 API Security Validator")
    st.caption(
        "Upload an OpenAPI spec or Postman collection, then run automated OWASP API "
        "Top 10 security tests against a staging target. Production targets are blocked."
    )

    # Sidebar history (always visible)
    history_selected = render_history_sidebar()
    if history_selected is not None:
        st.session_state[SESSION_LAST_SCAN] = history_selected
        st.info(f"Loaded scan from history: `{history_selected.scan_id[:8]}`")

    # Input panel
    inputs = render_input_panel()

    # Settings expander (returns ScanConfig with target_base_url filled in)
    config = render_settings_expander(default_target=inputs.target_url)
    # Override with the URL from the input panel
    config = config.model_copy(update={"target_base_url": inputs.target_url})

    # Scan trigger
    if inputs.scan_requested:
        _execute_scan(inputs, config)

    # Display the most recent scan result (from current session or history)
    last_scan: ScanResult | None = st.session_state.get(SESSION_LAST_SCAN)
    if last_scan is not None:
        st.markdown("---")
        render_findings(last_scan)


def _execute_scan(inputs, config) -> None:
    """Parse spec, run orchestrator, store result in session state."""
    if inputs.spec_bytes is None:
        st.error("Please upload a spec file first.")
        return

    # Parse spec
    try:
        spec = parse_spec(inputs.spec_bytes)
    except UnsupportedSpecError as e:
        st.error(f"Unsupported spec format: {e}")
        return
    except SpecParseError as e:
        st.error(f"Failed to parse spec: {e}")
        if e.errors:
            with st.expander("Parser error details"):
                for err in e.errors:
                    st.code(err)
        return
    except APISecurityError as e:
        st.error(f"Spec error: {e}")
        return

    st.success(
        f"Parsed spec: **{spec.name}** "
        f"({spec.endpoint_count()} endpoints, {len(spec.auth_schemes)} auth schemes)"
    )
    if spec.warnings:
        with st.expander(f"⚠️ {len(spec.warnings)} parse warning(s)"):
            for w in spec.warnings:
                st.caption(f"`{w.code}` — {w.message}")

    # Construct orchestrator
    orchestrator = ScanOrchestrator(
        config=config,
        auth_context=inputs.auth_context,
    )

    # Stream progress
    final_event = render_progress(orchestrator.run_scan(spec))

    # Get the persisted ScanResult — orchestrator should expose _last_scan_result
    scan_result = getattr(orchestrator, "_last_scan_result", None)
    if scan_result is None and final_event is not None:
        # Build a minimal ScanResult from the final progress event
        # (Fallback for older orchestrator implementations)
        from datetime import datetime

        from core.models import ScanResult, ScanStatus, ScanType
        scan_result = ScanResult(
            scan_type=ScanType.API,
            target=config.target_base_url,
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            findings=final_event.partial_findings or [],
        )

    if scan_result is None:
        st.error("Scan did not produce a result.")
        return

    st.session_state[SESSION_LAST_SCAN] = scan_result
    st.success(f"Scan complete — {len(scan_result.findings)} findings.")
