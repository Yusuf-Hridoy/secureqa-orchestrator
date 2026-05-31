"""Tests for LLMExplainer."""

from unittest.mock import MagicMock

from core.api_security.execution.llm_explainer import (
    Explanation,
    LLMExplainer,
)
from core.api_security.execution.models import ExecutionResult, ExecutionStatus
from core.api_security.execution.rule_classifier import ClassificationOutcome
from core.api_security.models import HTTPMethod
from core.api_security.test_models import (
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)
from core.llm_client import LLMOutputError
from core.models import Severity


def _make_test(category=OWASPAPICategory.API1_BOLA, path="/users/{id}"):
    return SecurityTest(
        owasp_category=category,
        name="test",
        description="x",
        rationale="x",
        target_endpoint_path=path,
        target_endpoint_method=HTTPMethod.GET,
        payload=TestPayload(method=HTTPMethod.GET, path=path),
    )


def _make_result():
    return ExecutionResult(
        test_id="t",
        status=ExecutionStatus.SUCCESS,
        http_status=200,
    )


def _make_outcome():
    return ClassificationOutcome(
        is_vulnerability=True,
        finding_score=0.9,
        rule_confidence=0.9,
        matched_indicators=[],
        suggested_severity=Severity.HIGH,
        explanation="x",
    )


def test_returns_explanation_on_success():
    client = MagicMock()
    client.generate_structured.return_value = Explanation(
        summary="BOLA on /users/{id}",
        details="The endpoint accepted a substituted ID and returned a 200.",
        remediation="Verify ownership before returning the resource.",
        references=["CWE-639"],
    )
    explainer = LLMExplainer(client=client)
    res = explainer.explain(
        _make_test(), _make_result(), _make_outcome(), Severity.HIGH
    )
    assert res.explanation is not None
    assert "BOLA" in res.explanation.summary
    assert res.used_cache is False


def test_caches_by_category_severity_path():
    client = MagicMock()
    client.generate_structured.return_value = Explanation(
        summary="x", details="x", remediation="x"
    )
    explainer = LLMExplainer(client=client)
    test = _make_test()
    result = _make_result()
    outcome = _make_outcome()

    r1 = explainer.explain(test, result, outcome, Severity.HIGH)
    r2 = explainer.explain(test, result, outcome, Severity.HIGH)
    assert r1.used_cache is False
    assert r2.used_cache is True
    assert client.generate_structured.call_count == 1


def test_different_severities_not_cached_together():
    client = MagicMock()
    client.generate_structured.return_value = Explanation(
        summary="x", details="x", remediation="x"
    )
    explainer = LLMExplainer(client=client)
    test = _make_test()
    explainer.explain(test, _make_result(), _make_outcome(), Severity.HIGH)
    explainer.explain(
        test, _make_result(), _make_outcome(), Severity.CRITICAL
    )
    assert client.generate_structured.call_count == 2


def test_fallback_explanation_on_failure():
    client = MagicMock()
    client.generate_structured.side_effect = LLMOutputError("validation failed")
    explainer = LLMExplainer(client=client)
    res = explainer.explain(
        _make_test(), _make_result(), _make_outcome(), Severity.HIGH
    )
    assert res.explanation is not None  # fallback used
    assert "OWASP" in res.explanation.references[0]


def test_clear_cache():
    client = MagicMock()
    client.generate_structured.return_value = Explanation(
        summary="x", details="x", remediation="x"
    )
    explainer = LLMExplainer(client=client)
    test = _make_test()
    explainer.explain(test, _make_result(), _make_outcome(), Severity.HIGH)
    explainer.clear_cache()
    explainer.explain(test, _make_result(), _make_outcome(), Severity.HIGH)
    assert client.generate_structured.call_count == 2
