"""Formatters for UI display. Pure functions, no streamlit imports."""

from core.models import Finding, Severity

# Severity color mapping (CSS/hex values)
SEVERITY_COLORS = {
    Severity.CRITICAL: "#DC2626",   # red-600
    Severity.HIGH: "#EA580C",       # orange-600
    Severity.MEDIUM: "#D97706",     # amber-600
    Severity.LOW: "#0891B2",        # cyan-600
    Severity.INFO: "#6B7280",       # gray-500
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "⚪",
}


def format_severity_badge(severity: Severity) -> str:
    """Return 'icon SEVERITY' string for inline display."""
    icon = SEVERITY_ICONS.get(severity, "⚪")
    return f"{icon} {severity.value.upper()}"


def format_finding_title(finding: Finding, max_length: int = 80) -> str:
    """Return truncated title with severity prefix."""
    icon = SEVERITY_ICONS.get(finding.severity, "⚪")
    title = truncate(finding.title, max_length)
    return f"{icon} {title}"


def format_latency(ms: float) -> str:
    """Human-readable latency: '123 ms' or '1.2 s'."""
    if ms < 1000:
        return f"{ms:.0f} ms"
    return f"{ms / 1000:.1f} s"


def truncate(text: str, max_length: int = 80) -> str:
    """Truncate text, add ellipsis if needed."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 1] + "…"


def severity_score(severity: Severity) -> int:
    """Sortable numeric score (higher = more severe)."""
    return {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }.get(severity, 0)
