"""LLM-generated human-readable explanations for findings."""

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

logger = get_logger("llm_explainer")


class Explanation(BaseModel):
    """Structured explanation from Gemini."""

    summary: str  # 1-sentence summary for report headers
    details: str  # 2-4 paragraphs of detail
    remediation: str  # actionable fix advice
    references: list[str] = Field(default_factory=list)  # CWE / OWASP refs


@dataclass
class ExplanationResult:
    explanation: Explanation | None
    used_cache: bool
    error: str | None = None


class LLMExplainer:
    """Generates explanations for findings. Cached aggressively."""

    def __init__(self, client: GeminiClient | None = None):
        self.client = client or GeminiClient()
        self._cache: dict[str, Explanation] = {}

    def explain(
        self,
        test: SecurityTest,
        result: ExecutionResult,
        rule_outcome: ClassificationOutcome,
        severity: Severity,
    ) -> ExplanationResult:
        cache_key = self._cache_key(test, severity)
        if cache_key in self._cache:
            return ExplanationResult(
                explanation=self._cache[cache_key], used_cache=True
            )

        prompt = self._build_prompt(test, result, rule_outcome, severity)
        try:
            explanation = self.client.generate_structured(
                prompt, response_model=Explanation
            )
            self._cache[cache_key] = explanation
            return ExplanationResult(
                explanation=explanation, used_cache=False
            )
        except LLMOutputError as e:
            logger.warning(
                f"LLM explanation failed for {test.name}: {e}"
            )
            return ExplanationResult(
                explanation=self._fallback_explanation(test, severity),
                used_cache=False,
                error=str(e),
            )
        except Exception as e:
            logger.error(f"Unexpected LLM error: {e}")
            return ExplanationResult(
                explanation=self._fallback_explanation(test, severity),
                used_cache=False,
                error=str(e),
            )

    def _cache_key(self, test: SecurityTest, severity: Severity) -> str:
        # Cache by (category, severity, generalized endpoint pattern)
        # Generalize path: /users/123 → /users/{id}
        path_pattern = test.target_endpoint_path  # already normalized
        sig = json.dumps(
            {
                "category": test.owasp_category.value,
                "severity": severity.value,
                "method": test.target_endpoint_method.value,
                "path_pattern": path_pattern,
            },
            sort_keys=True,
        )
        return hashlib.sha256(sig.encode()).hexdigest()[:16]

    def _build_prompt(
        self,
        test: SecurityTest,
        result: ExecutionResult,
        rule_outcome: ClassificationOutcome,
        severity: Severity,
    ) -> str:
        return f"""You are a security engineer writing a finding for a vulnerability report.
The target audience: a QA engineer or developer who will need to fix this issue.

Finding details:
- OWASP Category: {test.owasp_category.value}
- Severity: {severity.value}
- Endpoint: {test.target_endpoint_method.value} {test.target_endpoint_path}
- Test rationale: {test.rationale}
- HTTP status returned: {result.http_status}
- Rule-based score: {rule_outcome.finding_score:.2f}

Generate a finding writeup. Respond ONLY with JSON matching this schema:
{{
  "summary": "1-sentence summary for the report header (under 100 chars)",
  "details": "2-4 paragraphs explaining what was tested, what was found, and why it matters. Be specific.",
  "remediation": "Actionable steps the developer can take to fix this. Include code/config examples if applicable.",
  "references": ["CWE-XXX: Name", "OWASP API Security 2023: API1:2023 ..."]
}}

Be technical and specific. Avoid generic phrases like "this could be exploited." Show the developer EXACTLY what to do.
"""

    def _fallback_explanation(
        self, test: SecurityTest, severity: Severity
    ) -> Explanation:
        """Generic fallback if LLM is unavailable."""
        return Explanation(
            summary=f"{test.owasp_category.value} finding on {test.target_endpoint_path}",
            details=test.rationale,
            remediation=(
                "Review the OWASP API Security Top 10 guidance for this category and "
                "apply appropriate validation, authentication, and access controls."
            ),
            references=[
                f"OWASP API Security Top 10: {test.owasp_category.value}"
            ],
        )

    def clear_cache(self) -> None:
        self._cache.clear()
