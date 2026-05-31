"""Tests for LLMClassifier. All Gemini calls mocked."""

from unittest.mock import MagicMock

from core.api_security.execution.llm_classifier import (
    LLMClassifier,
    LLMVerdict,
)
from core.api_security.execution.models import ExecutionResult, ExecutionStatus
from core.api_security.execution.rule_classifier import ClassificationOutcome
from core.api_security.models import HTTPMethod
from core.api_security.test_models import (
    ExpectedIndicator,
    IndicatorType,
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)
from core.llm_client import LLMOutputError
from core.models import Severity


def _make_test():
    return SecurityTest(
        owasp_category=OWASPAPICategory.API1_BOLA,
        name="bola-test",
        description="x",
        rationale="x",
        target_endpoint_path="/users/{id}",
        target_endpoint_method=HTTPMethod.GET,
        payload=TestPayload(method=HTTPMethod.GET, path="/users/1"),
        indicators=[
            ExpectedIndicator(
                type=IndicatorType.STATUS_CODE_IS, value=200, weight=1.0
            ),
        ],
    )


def _make_result(body=""):
    return ExecutionResult(
        test_id="t1",
        status=ExecutionStatus.SUCCESS,
        http_status=200,
        response_body=body,
        latency_ms=100,
    )


def _make_outcome():
    return ClassificationOutcome(
        is_vulnerability=True,
        finding_score=0.6,
        rule_confidence=0.3,
        matched_indicators=[],
        suggested_severity=Severity.HIGH,
        explanation="ambiguous",
    )


def test_returns_verdict_on_success():
    client = MagicMock()
    client.generate_structured.return_value = LLMVerdict(
        is_vulnerability=True,
        severity=Severity.HIGH,
        confidence=0.85,
        explanation="The response confirms unauthorized resource access.",
    )
    clf = LLMClassifier(client=client)
    res = clf.tie_break(_make_test(), _make_result(), _make_outcome())
    assert res.verdict is not None
    assert res.verdict.is_vulnerability is True
    assert res.verdict.severity == Severity.HIGH
    assert res.used_cache is False


def test_caches_repeat_calls():
    client = MagicMock()
    client.generate_structured.return_value = LLMVerdict(
        is_vulnerability=False,
        severity=Severity.LOW,
        confidence=0.5,
        explanation="x",
    )
    clf = LLMClassifier(client=client)
    test = _make_test()
    result = _make_result()
    outcome = _make_outcome()

    r1 = clf.tie_break(test, result, outcome)
    r2 = clf.tie_break(test, result, outcome)
    assert r1.used_cache is False
    assert r2.used_cache is True
    assert client.generate_structured.call_count == 1


def test_returns_none_on_llm_failure():
    client = MagicMock()
    client.generate_structured.side_effect = LLMOutputError("validation failed")
    clf = LLMClassifier(client=client)
    res = clf.tie_break(_make_test(), _make_result(), _make_outcome())
    assert res.verdict is None
    assert res.error is not None


def test_returns_none_on_unexpected_error():
    client = MagicMock()
    client.generate_structured.side_effect = RuntimeError("boom")
    clf = LLMClassifier(client=client)
    res = clf.tie_break(_make_test(), _make_result(), _make_outcome())
    assert res.verdict is None


def test_different_response_bodies_not_cached_together():
    client = MagicMock()
    client.generate_structured.return_value = LLMVerdict(
        is_vulnerability=True,
        severity=Severity.MEDIUM,
        confidence=0.7,
        explanation="x",
    )
    clf = LLMClassifier(client=client)
    test = _make_test()

    clf.tie_break(test, _make_result(body="one"), _make_outcome())
    clf.tie_break(test, _make_result(body="two"), _make_outcome())
    assert client.generate_structured.call_count == 2


def test_clear_cache():
    client = MagicMock()
    client.generate_structured.return_value = LLMVerdict(
        is_vulnerability=False,
        severity=Severity.LOW,
        confidence=0.5,
        explanation="x",
    )
    clf = LLMClassifier(client=client)
    test = _make_test()
    result = _make_result()
    outcome = _make_outcome()

    clf.tie_break(test, result, outcome)
    clf.clear_cache()
    clf.tie_break(test, result, outcome)
    assert client.generate_structured.call_count == 2
