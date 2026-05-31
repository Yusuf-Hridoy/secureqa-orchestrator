"""Rule-based classifier: matches ExpectedIndicators against ExecutionResults."""

import re
from dataclasses import dataclass

from core.api_security.execution.models import ExecutionResult, ExecutionStatus
from core.api_security.test_models import (
    ExpectedIndicator,
    IndicatorType,
    SecurityTest,
)
from core.logging_config import get_logger
from core.models import Severity

logger = get_logger("rule_classifier")


@dataclass
class ClassificationOutcome:
    """Output of classifying one test result."""

    is_vulnerability: bool  # True if finding_score >= 0.5
    finding_score: float  # 0.0 – 1.0 (weighted ratio of matched indicators)
    rule_confidence: float  # 0.0 – 1.0 (how certain the rule-based result is)
    matched_indicators: list[ExpectedIndicator]
    suggested_severity: Severity
    explanation: str


class RuleBasedClassifier:
    """Pure-function classifier: SecurityTest + ExecutionResult → ClassificationOutcome."""

    # Threshold above which we say "this is a finding"
    FINDING_THRESHOLD = 0.5
    # Threshold above which rule confidence is considered "decisive" (no LLM tie-break needed)
    DECISIVE_THRESHOLD = 0.5

    def classify(
        self, test: SecurityTest, result: ExecutionResult
    ) -> ClassificationOutcome:
        # Skipped or errored tests are not findings
        if result.status != ExecutionStatus.SUCCESS:
            return ClassificationOutcome(
                is_vulnerability=False,
                finding_score=0.0,
                rule_confidence=1.0,  # we're certain it's NOT a vuln (test didn't run)
                matched_indicators=[],
                suggested_severity=Severity.INFO,
                explanation=f"Test {result.status.value}; no finding.",
            )

        matched: list[ExpectedIndicator] = []
        total_weight = 0.0
        matched_weight = 0.0

        for ind in test.indicators:
            total_weight += ind.weight
            if self._indicator_matches(ind, result):
                matched.append(ind)
                matched_weight += ind.weight

        finding_score = (
            (matched_weight / total_weight) if total_weight > 0 else 0.0
        )
        is_vuln = finding_score >= self.FINDING_THRESHOLD

        # Confidence calculation:
        # - If all indicators matched OR none matched → high confidence
        # - If a mix matched → lower confidence (genuinely ambiguous)
        if not test.indicators:
            rule_confidence = 0.0
        elif len(matched) == len(test.indicators) or len(matched) == 0:
            rule_confidence = 1.0
        else:
            ratio = len(matched) / len(test.indicators)
            # Confidence peaks at extremes (0% or 100% matched)
            rule_confidence = 1.0 - 2.0 * abs(ratio - 0.5)
            rule_confidence = max(
                0.0, min(1.0, 1.0 - rule_confidence + 0.3)
            )
            # Simpler: clamp
            rule_confidence = min(
                1.0, max(0.0, abs(ratio - 0.5) * 2.0 + 0.2)
            )

        severity = test.severity_hint if is_vuln else Severity.INFO
        explanation = self._build_explanation(
            matched, test.indicators, finding_score
        )

        return ClassificationOutcome(
            is_vulnerability=is_vuln,
            finding_score=finding_score,
            rule_confidence=rule_confidence,
            matched_indicators=matched,
            suggested_severity=severity,
            explanation=explanation,
        )

    # ---------- Indicator matchers ----------

    def _indicator_matches(
        self, ind: ExpectedIndicator, result: ExecutionResult
    ) -> bool:
        try:
            return self._dispatch(ind, result)
        except Exception as e:
            logger.warning(f"Indicator match failed ({ind.type.value}): {e}")
            return False

    def _dispatch(
        self, ind: ExpectedIndicator, result: ExecutionResult
    ) -> bool:
        status = result.http_status
        headers_lower = {
            k.lower(): v for k, v in result.response_headers.items()
        }
        body = result.response_body or ""

        if ind.type == IndicatorType.STATUS_CODE_IS:
            return status == ind.value

        if ind.type == IndicatorType.STATUS_CODE_IN:
            values = (
                ind.value if isinstance(ind.value, list) else [ind.value]
            )
            return status in values

        if ind.type == IndicatorType.STATUS_CODE_NOT:
            return status != ind.value

        if ind.type == IndicatorType.HEADER_MISSING:
            target = (ind.target or "").lower()
            return target not in headers_lower

        if ind.type == IndicatorType.HEADER_PRESENT:
            target = (ind.target or "").lower()
            return target in headers_lower

        if ind.type == IndicatorType.HEADER_VALUE_IS:
            target = (ind.target or "").lower()
            return headers_lower.get(target) == ind.value

        if ind.type == IndicatorType.BODY_CONTAINS:
            return str(ind.value) in body

        if ind.type == IndicatorType.BODY_NOT_CONTAINS:
            return str(ind.value) not in body

        if ind.type == IndicatorType.BODY_MATCHES_REGEX:
            try:
                return bool(re.search(str(ind.value), body))
            except re.error:
                return False

        if ind.type == IndicatorType.RESPONSE_TIME_GT:
            return result.latency_ms > float(ind.value)

        if ind.type == IndicatorType.RESPONSE_SIZE_GT:
            return result.response_size_bytes > int(ind.value)

        return False

    def _build_explanation(
        self,
        matched: list[ExpectedIndicator],
        all_indicators: list[ExpectedIndicator],
        score: float,
    ) -> str:
        if not matched:
            return "No indicators matched; response appears safe for this check."
        if len(matched) == len(all_indicators):
            return f"All {len(matched)} indicators matched (score={score:.2f}). Strong evidence."
        return (
            f"{len(matched)} of {len(all_indicators)} indicators matched "
            f"(score={score:.2f}). Partial evidence — may need LLM review."
        )
