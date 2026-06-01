"""Tests for UI formatters."""


from core.api_security.ui.formatters import (
    SEVERITY_COLORS,
    SEVERITY_ICONS,
    format_finding_title,
    format_latency,
    format_severity_badge,
    severity_score,
    truncate,
)
from core.models import Finding, Severity


def test_severity_colors_complete():
    for sev in Severity:
        assert sev in SEVERITY_COLORS


def test_severity_icons_complete():
    for sev in Severity:
        assert sev in SEVERITY_ICONS


def test_format_severity_badge():
    badge = format_severity_badge(Severity.CRITICAL)
    assert "CRITICAL" in badge
    assert "🔴" in badge


def test_format_finding_title_truncates():
    f = Finding(
        title="A" * 200,
        description="x",
        severity=Severity.HIGH,
        confidence=0.9,
        category="x",
    )
    out = format_finding_title(f, max_length=50)
    # icon + space + truncated title
    assert len(out) <= 60
    assert out.endswith("…")


def test_format_latency_ms():
    assert format_latency(120) == "120 ms"


def test_format_latency_seconds():
    assert "s" in format_latency(2500)
    assert format_latency(1200) == "1.2 s"


def test_truncate_short_unchanged():
    assert truncate("short", 50) == "short"


def test_truncate_long_with_ellipsis():
    out = truncate("A" * 100, 20)
    assert len(out) == 20
    assert out.endswith("…")


def test_severity_score_order():
    assert severity_score(Severity.CRITICAL) > severity_score(Severity.HIGH)
    assert severity_score(Severity.HIGH) > severity_score(Severity.LOW)
    assert severity_score(Severity.LOW) > severity_score(Severity.INFO)
