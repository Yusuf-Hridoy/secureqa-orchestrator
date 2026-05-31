"""LLM-based classifier for ambiguous security test results.

Invoked when RuleBasedClassifier returns rule_confidence < 0.5 AND finding_score
is above the finding threshold. Gemini reviews the request + response and provides
a final verdict.
"""

import hashlib
import json
from dataclasses import dataclass

from pydantic import BaseModel, Field

from core.api_security.execution.models import ExecutionResult
from core.api_security.execution.rule_classifier import ClassificationOutcome
from core.api_security.test_models import SecurityTest
from core.llm_client import GeminiClient, LLMOutputError
from core.logging_config import get_logger
from core.models import Severity

logger = get_logger("llm_classifier")


class LLMVerdict(BaseModel):
    """Structured Gemini response for tie-break classification."""

    is_vulnerability: bool
    severity: Severity = Severity.INFO
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    suggested_remediation: str | None = None


@dataclass
class TieBreakResult:
    """Outcome of running the LLM tie-breaker."""

    verdict: LLMVerdict | None  # None if LLM failed
    used_cache: bool
    error: str | None = None


class LLMClassifier:
    """Gemini-backed tie-breaker for ambiguous rule classifications."""

    def __init__(self, client: GeminiClient | None = None):
        self.client = client or GeminiClient()
        self._cache: dict[str, LLMVerdict] = {}

    def tie_break(
        self,
        test: SecurityTest,
        result: ExecutionResult,
        rule_outcome: ClassificationOutcome,
    ) -> TieBreakResult:
        cache_key = self._cache_key(test, result)
        if cache_key in self._cache:
            return TieBreakResult(
                verdict=self._cache[cache_key], used_cache=True
            )

        prompt = self._build_prompt(test, result, rule_outcome)
        try:
            verdict = self.client.generate_structured(
                prompt, response_model=LLMVerdict
            )
            self._cache[cache_key] = verdict
            logger.info(
                f"LLM verdict for {test.name}: is_vuln={verdict.is_vulnerability}, "
                f"severity={verdict.severity.value}, confidence={verdict.confidence}"
            )
            return TieBreakResult(verdict=verdict, used_cache=False)
        except LLMOutputError as e:
            logger.warning(
                f"LLM tie-break failed for {test.name}: {e}"
            )
            return TieBreakResult(
                verdict=None, used_cache=False, error=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected LLM error: {e}")
            return TieBreakResult(
                verdict=None, used_cache=False, error=str(e)
            )

    def _cache_key(
        self, test: SecurityTest, result: ExecutionResult
    ) -> str:
        sig = json.dumps(
            {
                "category": test.owasp_category.value,
                "test_name": test.name,
                "http_status": result.http_status,
                "body_hash": hashlib.sha256(
                    result.response_body.encode()
                ).hexdigest()[:16],
                "has_indicators_matched": True,
            },
            sort_keys=True,
        )
        return hashlib.sha256(sig.encode()).hexdigest()[:16]

    def _build_prompt(
        self,
        test: SecurityTest,
        result: ExecutionResult,
        rule_outcome: ClassificationOutcome,
    ) -> str:
        # Truncate response body for prompt
        body_excerpt = result.response_body[:2000]

        matched_descriptions = [
            f"- {ind.type.value} (weight {ind.weight}): {ind.description}"
            for ind in rule_outcome.matched_indicators
        ]

        return f"""You are a security engineer reviewing an automated API security test result.
The rule-based classifier flagged this as potentially a vulnerability but is uncertain.
Your job is to make the final call: is this a real vulnerability or a false positive?

OWASP Category: {test.owasp_category.value}
Test name: {test.name}
Test rationale: {test.rationale}

Request executed:
- Method: {result.final_method.value}
- URL: {result.final_url}
- Final path: {test.payload.path}

Response received:
- HTTP status: {result.http_status}
- Latency: {result.latency_ms:.0f} ms
- Body (truncated to 2000 chars):
{body_excerpt}

Indicators that matched (rule-based):
{chr(10).join(matched_descriptions) if matched_descriptions else "(none)"}

Rule-based finding_score: {rule_outcome.finding_score:.2f}
Rule-based confidence: {rule_outcome.rule_confidence:.2f}

Respond ONLY with a JSON object matching this schema:
{{
  "is_vulnerability": true | false,
  "severity": "info" | "low" | "medium" | "high" | "critical",
  "confidence": 0.0 - 1.0,
  "explanation": "1-3 sentences explaining your reasoning",
  "suggested_remediation": "optional remediation advice or null"
}}

Be precise and conservative — only mark as vulnerability if you have clear evidence.
"""

    def clear_cache(self) -> None:
        self._cache.clear()
