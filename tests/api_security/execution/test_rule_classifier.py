"""Tests for RuleBasedClassifier."""


from core.api_security.execution.models import ExecutionResult, ExecutionStatus
from core.api_security.execution.rule_classifier import RuleBasedClassifier
from core.api_security.models import HTTPMethod
from core.api_security.test_models import (
    ExpectedIndicator,
    IndicatorType,
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)
from core.models import Severity


def _make_test(indicators: list[ExpectedIndicator], severity=Severity.HIGH):
    return SecurityTest(
        owasp_category=OWASPAPICategory.API1_BOLA,
        name="t",
        description="x",
        rationale="x",
        target_endpoint_path="/x",
        target_endpoint_method=HTTPMethod.GET,
        payload=TestPayload(method=HTTPMethod.GET, path="/x"),
        indicators=indicators,
        severity_hint=severity,
    )


def _make_result(
    status=ExecutionStatus.SUCCESS,
    http_status=200,
    body="",
    headers=None,
    latency_ms=10,
):
    return ExecutionResult(
        test_id="t",
        status=status,
        http_status=http_status,
        response_body=body,
        response_headers=headers or {},
        latency_ms=latency_ms,
    )


def test_skipped_test_no_finding():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.STATUS_CODE_IS, value=200, weight=1.0
            )
        ]
    )
    result = _make_result(status=ExecutionStatus.SKIPPED)
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.is_vulnerability is False


def test_status_code_is_matched():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.STATUS_CODE_IS, value=200, weight=1.0
            )
        ]
    )
    result = _make_result(http_status=200)
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.is_vulnerability is True
    assert outcome.finding_score == 1.0


def test_status_code_in_matched():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.STATUS_CODE_IN,
                value=[200, 201],
                weight=1.0,
            )
        ]
    )
    result = _make_result(http_status=201)
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.is_vulnerability is True


def test_status_code_not_matched():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.STATUS_CODE_NOT, value=401, weight=1.0
            )
        ]
    )
    result = _make_result(http_status=200)  # not 401 → finding
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.is_vulnerability is True


def test_header_missing():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.HEADER_MISSING,
                target="Strict-Transport-Security",
                weight=1.0,
            )
        ]
    )
    result = _make_result(
        headers={"Content-Type": "application/json"}  # no HSTS
    )
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.is_vulnerability is True


def test_header_present_not_missing():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.HEADER_MISSING,
                target="X-Frame-Options",
                weight=1.0,
            )
        ]
    )
    result = _make_result(headers={"X-Frame-Options": "DENY"})
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.is_vulnerability is False


def test_body_contains():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.BODY_CONTAINS,
                value="Traceback",
                weight=1.0,
            )
        ]
    )
    result = _make_result(body="Internal error: Traceback ...")
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.is_vulnerability is True


def test_body_regex():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.BODY_MATCHES_REGEX,
                value=r"\bSQLException\b",
                weight=1.0,
            )
        ]
    )
    result = _make_result(body="org.h2.jdbc.SQLException: ...")
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.is_vulnerability is True


def test_response_time_gt():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.RESPONSE_TIME_GT,
                value=3000,
                weight=1.0,
            )
        ]
    )
    result = _make_result(latency_ms=4500)
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.is_vulnerability is True


def test_weighted_partial_match_drops_confidence():
    """1 of 2 indicators matched → ambiguous → confidence below 1.0."""
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.STATUS_CODE_IS, value=200, weight=1.0
            ),
            ExpectedIndicator(
                type=IndicatorType.BODY_CONTAINS,
                value="admin",
                weight=1.0,
            ),
        ]
    )
    result = _make_result(
        http_status=200, body="just a normal response"
    )
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.rule_confidence < 1.0


def test_all_indicators_match_high_confidence():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.STATUS_CODE_IS, value=200, weight=1.0
            ),
            ExpectedIndicator(
                type=IndicatorType.BODY_CONTAINS, value="ok", weight=1.0
            ),
        ]
    )
    result = _make_result(http_status=200, body='{"status":"ok"}')
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.rule_confidence >= 0.8
    assert outcome.is_vulnerability is True


def test_no_indicators_match_below_threshold():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.STATUS_CODE_IS, value=200, weight=1.0
            ),
        ]
    )
    result = _make_result(http_status=404)
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.finding_score == 0.0
    assert outcome.is_vulnerability is False
    assert outcome.suggested_severity == Severity.INFO


def test_severity_propagated_from_test_when_finding():
    test = _make_test(
        [
            ExpectedIndicator(
                type=IndicatorType.STATUS_CODE_IS, value=200, weight=1.0
            )
        ],
        severity=Severity.CRITICAL,
    )
    result = _make_result(http_status=200)
    outcome = RuleBasedClassifier().classify(test, result)
    assert outcome.suggested_severity == Severity.CRITICAL
