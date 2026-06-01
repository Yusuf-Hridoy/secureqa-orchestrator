"""Tests for the filter_findings function."""


from core.api_security.ui.filters import filter_findings
from core.models import Finding, Severity


def _f(title="t", severity=Severity.HIGH, category="API1_BOLA", confidence=0.8, description="x"):
    return Finding(
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        category=category,
    )


def test_no_filters_returns_all():
    findings = [_f(), _f(severity=Severity.LOW)]
    assert len(filter_findings(findings)) == 2


def test_filter_by_severity():
    findings = [
        _f(severity=Severity.CRITICAL),
        _f(severity=Severity.LOW),
        _f(severity=Severity.HIGH),
    ]
    out = filter_findings(findings, severities={Severity.CRITICAL, Severity.HIGH})
    assert len(out) == 2
    assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in out)


def test_filter_by_category():
    findings = [
        _f(category="API1_BOLA"),
        _f(category="API8_MISCONFIGURATION"),
    ]
    out = filter_findings(findings, categories={"API1_BOLA"})
    assert len(out) == 1
    assert out[0].category == "API1_BOLA"


def test_filter_by_min_confidence():
    findings = [
        _f(confidence=0.3),
        _f(confidence=0.7),
        _f(confidence=0.95),
    ]
    out = filter_findings(findings, min_confidence=0.6)
    assert len(out) == 2


def test_filter_by_search_text_in_title():
    findings = [
        _f(title="BOLA on /users/{id}", category="API1_BOLA"),
        _f(title="Missing HSTS header", category="API8_MISCONFIGURATION"),
    ]
    out = filter_findings(findings, search_text="BOLA")
    assert len(out) == 1


def test_filter_by_search_text_case_insensitive():
    findings = [_f(title="BOLA on /users")]
    assert len(filter_findings(findings, search_text="bola")) == 1


def test_filter_by_search_in_description():
    findings = [
        _f(description="The endpoint returned 200 without auth"),
        _f(description="A different issue entirely"),
    ]
    out = filter_findings(findings, search_text="without auth")
    assert len(out) == 1


def test_combined_filters_are_and():
    findings = [
        _f(severity=Severity.HIGH, category="API1_BOLA", confidence=0.9),
        _f(severity=Severity.HIGH, category="API8", confidence=0.9),
        _f(severity=Severity.LOW, category="API1_BOLA", confidence=0.9),
    ]
    out = filter_findings(
        findings,
        severities={Severity.HIGH},
        categories={"API1_BOLA"},
    )
    assert len(out) == 1
