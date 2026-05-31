"""Resolves {{placeholder}} substitutions in SecurityTest payloads using AuthContext."""

import re
from dataclasses import dataclass

from core.api_security.execution.models import AuthContext
from core.api_security.test_models import SecurityTest, TestPayload
from core.logging_config import get_logger

logger = get_logger("auth_context")

PLACEHOLDER_PATTERN = re.compile(r"\{\{([^}]+)\}\}")


@dataclass
class ResolutionResult:
    """Outcome of attempting to resolve placeholders in a SecurityTest."""

    resolved_test: SecurityTest | None
    skip_reason: str | None
    used_placeholders: list[str]

    @property
    def was_resolved(self) -> bool:
        return self.resolved_test is not None


class AuthContextResolver:
    """Substitutes placeholders in SecurityTest payloads with AuthContext values."""

    def __init__(self, auth_context: AuthContext):
        self.ctx = auth_context

    def resolve(self, test: SecurityTest) -> ResolutionResult:
        """Resolve all placeholders in test.payload. Skip if required values missing."""
        placeholders_found: set[str] = set()

        # Find all placeholders across path, headers, body, query, path_params
        for text in self._collect_strings(test.payload):
            for match in PLACEHOLDER_PATTERN.finditer(text):
                placeholders_found.add(match.group(1).strip())

        # Resolve each
        substitutions: dict[str, str] = {}
        missing: list[str] = []
        for ph in placeholders_found:
            value = self._lookup(ph)
            if value is None:
                missing.append(ph)
            else:
                substitutions[ph] = value

        if missing:
            return ResolutionResult(
                resolved_test=None,
                skip_reason=(
                    f"Test requires placeholders not in AuthContext: {missing}. "
                    "Provide these tokens to enable this test."
                ),
                used_placeholders=list(placeholders_found),
            )

        # Apply substitutions
        new_payload = self._substitute_payload(test.payload, substitutions)
        resolved = test.model_copy(update={"payload": new_payload})

        return ResolutionResult(
            resolved_test=resolved,
            skip_reason=None,
            used_placeholders=list(placeholders_found),
        )

    def _collect_strings(self, payload: TestPayload) -> list[str]:
        """All string fields in the payload that might contain placeholders."""
        out = [payload.path]
        out.extend(payload.path_params.values())
        out.extend(payload.query_params.values())
        out.extend(payload.headers.values())
        if isinstance(payload.body, str):
            out.append(payload.body)
        elif isinstance(payload.body, dict):
            out.extend(self._stringify_dict_values(payload.body))
        return out

    def _stringify_dict_values(self, d: dict) -> list[str]:
        result = []
        for v in d.values():
            if isinstance(v, str):
                result.append(v)
            elif isinstance(v, dict):
                result.extend(self._stringify_dict_values(v))
        return result

    def _lookup(self, placeholder: str) -> str | None:
        """Find the value for a placeholder, or None if unknown."""
        # Try known fields first
        key_map = {
            "bearer_token": self.ctx.bearer_token,
            "regular_user_token": self.ctx.regular_user_token,
            "admin_user_token": self.ctx.admin_user_token,
            "user_a_token": self.ctx.user_a_token,
            "user_b_token": self.ctx.user_b_token,
            "user_b_resource_id": self.ctx.user_b_resource_id,
            "api_key": self.ctx.api_key,
        }
        if placeholder in key_map:
            secret = key_map[placeholder]
            if secret is None:
                return None
            return secret.get_secret_value() if hasattr(secret, "get_secret_value") else str(secret)

        # Fall back to extras
        return self.ctx.extras.get(placeholder)

    def _substitute_payload(self, payload: TestPayload, subs: dict[str, str]) -> TestPayload:
        """Return a new TestPayload with placeholders replaced."""

        def replace_in_str(s: str) -> str:
            def replace(m):
                key = m.group(1).strip()
                return subs.get(key, m.group(0))

            return PLACEHOLDER_PATTERN.sub(replace, s)

        def replace_in_dict(d: dict) -> dict:
            new = {}
            for k, v in d.items():
                if isinstance(v, str):
                    new[k] = replace_in_str(v)
                elif isinstance(v, dict):
                    new[k] = replace_in_dict(v)
                else:
                    new[k] = v
            return new

        new_body = payload.body
        if isinstance(payload.body, str):
            new_body = replace_in_str(payload.body)
        elif isinstance(payload.body, dict):
            new_body = replace_in_dict(payload.body)

        return payload.model_copy(
            update={
                "path": replace_in_str(payload.path),
                "path_params": {
                    k: replace_in_str(v) for k, v in payload.path_params.items()
                },
                "query_params": {
                    k: replace_in_str(v) for k, v in payload.query_params.items()
                },
                "headers": {
                    k: replace_in_str(v) for k, v in payload.headers.items()
                },
                "body": new_body,
            }
        )
