"""LLM payload helper for security test generators.

Uses Gemini 2.5 Flash Lite to generate creative payloads for ambiguous cases.
Results are cached in memory per (endpoint signature + category) to avoid
hitting the API multiple times for the same input.

Fail-safe: if the LLM call fails or returns invalid output, the helper returns
an empty list. Rule-based fallback is always available in the generator itself.
"""

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field

from core.api_security.models import Endpoint
from core.api_security.test_models import OWASPAPICategory
from core.llm_client import GeminiClient, LLMOutputError
from core.logging_config import get_logger

logger = get_logger("llm_helper")


class LLMPayloadSuggestion(BaseModel):
    """One LLM-generated payload suggestion."""

    payload_description: str
    request_body: dict[str, Any] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    rationale: str


class LLMPayloadResponse(BaseModel):
    """Structured response from the LLM."""

    suggestions: list[LLMPayloadSuggestion] = Field(default_factory=list)


class LLMPayloadHelper:
    """Generates creative payloads for security tests via Gemini.

    Cache-on-success, fail-safe-on-error.
    """

    def __init__(self, client: GeminiClient | None = None, max_suggestions: int = 3):
        self.client = client or GeminiClient()
        self.max_suggestions = max_suggestions
        self._cache: dict[str, list[LLMPayloadSuggestion]] = {}

    def _cache_key(self, endpoint: Endpoint, category: OWASPAPICategory) -> str:
        """Deterministic key per (endpoint, category)."""
        sig = json.dumps(
            {
                "path": endpoint.path,
                "method": endpoint.method.value,
                "category": category.value,
                "has_body": endpoint.request_body is not None,
            },
            sort_keys=True,
        )
        return hashlib.sha256(sig.encode()).hexdigest()[:16]

    def suggest_payloads(
        self,
        endpoint: Endpoint,
        category: OWASPAPICategory,
    ) -> list[LLMPayloadSuggestion]:
        """Get LLM-generated payload suggestions, with caching."""
        cache_key = self._cache_key(endpoint, category)
        if cache_key in self._cache:
            logger.debug(f"LLM payload cache hit for {cache_key}")
            return self._cache[cache_key]

        prompt = self._build_prompt(endpoint, category)
        try:
            result = self.client.generate_structured(prompt, response_model=LLMPayloadResponse)
            suggestions = result.suggestions[: self.max_suggestions]
            self._cache[cache_key] = suggestions
            logger.info(
                f"LLM generated {len(suggestions)} payload(s) for {endpoint.method.value} "
                f"{endpoint.path} / {category.value}"
            )
            return suggestions
        except LLMOutputError as e:
            logger.warning(
                f"LLM payload generation failed for {endpoint.path}: {e}. "
                "Falling back to rule-based only."
            )
            self._cache[cache_key] = []
            return []
        except Exception as e:
            logger.warning(f"Unexpected LLM error: {e}. Falling back to rule-based.")
            self._cache[cache_key] = []
            return []

    def _build_prompt(self, endpoint: Endpoint, category: OWASPAPICategory) -> str:
        """Construct the prompt for Gemini."""
        category_guidance = {
            OWASPAPICategory.API1_BOLA: (
                "Generate payloads that test for Broken Object-Level Authorization. "
                "Focus on cross-tenant ID substitution and predictable ID enumeration."
            ),
            OWASPAPICategory.API2_BROKEN_AUTH: (
                "Generate payloads that test for broken authentication. "
                "Focus on missing tokens, malformed JWTs, expired tokens, weak credentials."
            ),
            OWASPAPICategory.API3_PROPERTY_AUTH: (
                "Generate request body payloads with extra fields that should be server-controlled. "
                "Focus on mass assignment: is_admin, role, account_balance, user_id, etc."
            ),
            OWASPAPICategory.API4_RESOURCE_CONSUMPTION: (
                "Generate payloads that test resource consumption limits. "
                "Focus on oversized payloads, deep nesting, large pagination values."
            ),
            OWASPAPICategory.API5_FUNCTION_AUTH: (
                "Generate payloads that probe function-level authorization. "
                "Focus on accessing admin-only endpoints as a regular user."
            ),
            OWASPAPICategory.API7_SSRF: (
                "Generate URL payloads that test for Server-Side Request Forgery. "
                "Focus on internal IPs (127.0.0.1, 169.254.169.254), file://, gopher://, internal hostnames."
            ),
            OWASPAPICategory.API8_MISCONFIGURATION: (
                "Generate payloads/requests that surface misconfiguration. "
                "Focus on triggering verbose errors, debug endpoints, default credentials."
            ),
            OWASPAPICategory.API9_INVENTORY: (
                "Generate payloads that probe for undocumented endpoints, methods, or versions. "
                "Focus on common admin paths, old API versions, debug endpoints."
            ),
        }

        endpoint_info = {
            "method": endpoint.method.value,
            "path": endpoint.path,
            "operation_id": endpoint.operation_id,
            "parameters": [
                {"name": p.name, "in": p.location.value, "required": p.required}
                for p in endpoint.parameters
            ],
            "has_request_body": endpoint.request_body is not None,
        }

        if endpoint.request_body:
            endpoint_info["body_schema"] = {
                "content_type": endpoint.request_body.content_type,
                "properties": list(endpoint.request_body.schema_spec.properties.keys()),
                "required": endpoint.request_body.schema_spec.required,
            }

        guidance = category_guidance.get(
            category, "Generate test payloads relevant to this OWASP category."
        )

        return f"""You are a security testing expert. Generate up to {self.max_suggestions} test payloads for the following API endpoint.

OWASP Category: {category.value}
Guidance: {guidance}

Endpoint:
{json.dumps(endpoint_info, indent=2)}

Generate payloads that are:
- SAFE: do not include destructive operations like DROP, DELETE FROM, rm -rf, or anything destructive to real systems
- TARGETED: each payload should map to a specific weakness in this OWASP category
- REALISTIC: payloads should be plausible attacker inputs, not theoretical

Respond with a JSON object matching this exact schema:
{{
  "suggestions": [
    {{
      "payload_description": "short label like 'BOLA cross-tenant id'",
      "request_body": {{}} or specific JSON body,
      "query_params": {{}} or specific query params as strings,
      "rationale": "one sentence explaining why this payload tests this vulnerability"
    }}
  ]
}}

If no meaningful payloads apply to this endpoint for this category, return an empty suggestions list.
"""

    def clear_cache(self) -> None:
        """Clear the in-memory cache (useful for tests)."""
        self._cache.clear()
