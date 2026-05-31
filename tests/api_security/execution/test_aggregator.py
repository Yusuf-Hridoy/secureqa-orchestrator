"""Tests for Aggregator."""


from core.api_security.execution.aggregator import Aggregator
from core.api_security.execution.llm_classifier import LLMVerdict
from core.api_security.execution.llm_explainer import Explanation
from core.api_security.execution.models import ExecutionResult, ExecutionStatus
from core.api_security.execution.rule_classifier import ClassificationOutcome
from core.api_security.models import HTTPMethod
from core.api_security.test_models import (
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)
from core.models import Finding, Severity


def _make_test(category=OWASPAPICategory.API1_BOLA):
    return SecurityTest(
        owasp_category=category,
        name="t",
        description="x",
        rationale="x",
        target_endpoint_path="/users/{id}",
        target_endpoint_method=HTTPMethod.GET,
        payload=TestPayload(method=HTTPMethod.GET, path="/users/1"),
    )


def _make_result():
    return ExecutionResult(
        test_id="t",
        status=ExecutionStatus.SUCCESS,
        http_status=200,
        response_body='{"id":1,"name":"alice"}',
    )


def _make_outcome(is_vuln=True, severity=Severity.HIGH, confidence=0.9):
    return ClassificationOutcome(
        is_vulnerability=is_vuln,
        finding_score=0.8,
        rule_confidence=confidence,
        matched_indicators=[],
        suggested_severity=severity,
        explanation="x",
    )


def test_no_finding_when_not_vuln():
    agg = Aggregator()
    out = agg.build_finding(
        _make_test(), _make_result(), _make_outcome(is_vuln=False)
    )
    assert out is None


def test_builds_finding_from_rule_outcome():
    agg = Aggregator()
    f = agg.build_finding(_make_test(), _make_result(), _make_outcome())
    assert f is not None
    assert f.severity == Severity.HIGH
    assert f.category == "API1_BOLA"
    assert "request" in f.evidence
    assert "response" in f.evidence


def test_llm_verdict_overrides_severity():
    agg = Aggregator()
    verdict = LLMVerdict(
        is_vulnerability=True,
        severity=Severity.CRITICAL,
        confidence=0.95,
        explanation="LLM confirmed BOLA",
    )
    f = agg.build_finding(
        _make_test(), _make_result(), _make_outcome(), llm_verdict=verdict
    )
    assert f.severity == Severity.CRITICAL
    assert f.confidence == 0.95
    assert "llm_verdict" in f.evidence


def test_explanation_populates_title_and_remediation():
    agg = Aggregator()
    explanation = Explanation(
        summary="BOLA on /users/{id} confirmed",
        details="Detailed analysis...",
        remediation="Add ownership check.",
        references=["CWE-639"],
    )
    f = agg.build_finding(
        _make_test(), _make_result(), _make_outcome(), explanation=explanation
    )
    assert f.title == "BOLA on /users/{id} confirmed"
    assert f.remediation == "Add ownership check."
    assert "references" in f.evidence


def test_sort_by_severity_then_confidence():
    agg = Aggregator()
    fs = [
        Finding(
            title="low",
            description="x",
            severity=Severity.LOW,
            confidence=0.9,
            category="x",
        ),
        Finding(
            title="critical",
            description="x",
            severity=Severity.CRITICAL,
            confidence=0.5,
            category="x",
        ),
        Finding(
            title="high-1",
            description="x",
            severity=Severity.HIGH,
            confidence=0.7,
            category="x",
        ),
        Finding(
            title="high-2",
            description="x",
            severity=Severity.HIGH,
            confidence=0.9,
            category="x",
        ),
    ]
    sorted_fs = agg.sort_findings(fs)
    assert sorted_fs[0].title == "critical"
    assert sorted_fs[1].title == "high-2"
    assert sorted_fs[2].title == "high-1"
    assert sorted_fs[3].title == "low"


def test_summary_counts():
    agg = Aggregator()
    fs = [
        Finding(
            title="x",
            description="x",
            severity=Severity.HIGH,
            confidence=0.9,
            category="API1_BOLA",
        ),
        Finding(
            title="x",
            description="x",
            severity=Severity.HIGH,
            confidence=0.9,
            category="API1_BOLA",
        ),
        Finding(
            title="x",
            description="x",
            severity=Severity.MEDIUM,
            confidence=0.8,
            category="API8_MISCONFIGURATION",
        ),
    ]
    results = [
        ExecutionResult(
            test_id="1", status=ExecutionStatus.SUCCESS, http_status=200
        ),
        ExecutionResult(
            test_id="2", status=ExecutionStatus.SKIPPED, skip_reason="x"
        ),
        ExecutionResult(test_id="3", status=ExecutionStatus.TIMEOUT),
    ]
    summary = agg.build_summary(fs, results, total_tests=5)
    assert summary["total_tests_planned"] == 5
    assert summary["total_findings"] == 3
    assert summary["findings_by_severity"]["high"] == 2
    assert summary["findings_by_category"]["API1_BOLA"] == 2
    assert summary["skipped_count"] == 1
    assert summary["error_count"] == 1
