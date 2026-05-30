"""OWASP API1: Broken Object-Level Authorization (BOLA) test generator.

Strategy:
- Look at every endpoint with PATH parameters (likely resource lookups).
- For each, generate substitution tests: ID = 0, 1, -1, 99999, sample-uuid.
- For endpoints requiring auth, mark requires_auth_context=True.
- Generate one cross-tenant test marked requires_two_users=True.
"""

from core.api_security.generators.base import Generator
from core.api_security.models import APISpec, Endpoint
from core.api_security.test_models import (
    ExpectedIndicator,
    IndicatorType,
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)
from core.models import Severity

# Substitution candidates for IDs — safe, non-destructive
SUBSTITUTION_IDS = [
    "0",
    "1",
    "-1",
    "99999",
    "00000000-0000-0000-0000-000000000000",  # UUID-zero
]


class BOLAGenerator(Generator):
    """API1: Broken Object-Level Authorization."""

    category = OWASPAPICategory.API1_BOLA
    name = "api1_bola"

    def generate(self, spec: APISpec) -> list[SecurityTest]:
        tests: list[SecurityTest] = []

        for endpoint in spec.endpoints:
            path_params = endpoint.path_parameters()
            if not path_params:
                continue  # nothing to substitute

            # Skip if multiple path params — too noisy for v1 (handle in 1.5)
            if len(path_params) > 1:
                continue

            param = path_params[0]
            requires_auth = bool(endpoint.security)

            # 1. ID substitution tests (5 per endpoint)
            for sub_id in SUBSTITUTION_IDS:
                tests.append(
                    self._build_id_substitution_test(
                        endpoint, param.name, sub_id, requires_auth
                    )
                )

            # 2. Cross-tenant test (marked requires_two_users)
            tests.append(self._build_cross_tenant_test(endpoint, param.name, requires_auth))

            # 3. LLM-assisted creative payloads (if enabled)
            if self.use_llm and self.llm_helper:
                llm_suggestions = self.llm_helper.suggest_payloads(endpoint, self.category)
                for s in llm_suggestions:
                    tests.append(self._build_from_llm(endpoint, s, requires_auth))

        return tests

    def _build_id_substitution_test(
        self, endpoint: Endpoint, param_name: str, sub_id: str, requires_auth: bool
    ) -> SecurityTest:
        path = endpoint.path.replace(f"{{{param_name}}}", sub_id)
        return SecurityTest(
            owasp_category=self.category,
            name=f"BOLA-{endpoint.operation_id or endpoint.path}-{param_name}={sub_id}",
            description=f"Substitute {param_name} with {sub_id!r} to test cross-resource access",
            rationale=(
                f"Endpoint {endpoint.method.value} {endpoint.path} takes a path "
                f"parameter '{param_name}'. Predictable substitution may reveal "
                f"access to resources owned by other users."
            ),
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=path,
                path_params={param_name: sub_id},
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=200,
                    description=(
                        "200 OK on a substituted ID with no auth context indicates "
                        "the endpoint does not enforce object ownership."
                    ),
                    weight=0.85,
                ),
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_NOT,
                    value=401,
                    description="A 401 here would mean auth is enforced (less likely to be BOLA).",
                    weight=0.3,
                ),
            ],
            severity_hint=Severity.HIGH,
            confidence_hint=0.7,
            requires_auth_context=requires_auth,
        )

    def _build_cross_tenant_test(
        self, endpoint: Endpoint, param_name: str, requires_auth: bool
    ) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"BOLA-cross-tenant-{endpoint.operation_id or endpoint.path}",
            description=(
                f"Authenticate as user A, request resource owned by user B "
                f"via {param_name}."
            ),
            rationale=(
                "Cross-tenant access is the classic BOLA: a valid user accessing "
                "another user's resources by changing the path parameter."
            ),
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path.replace(f"{{{param_name}}}", "{{userB_resource_id}}"),
                path_params={param_name: "{{userB_resource_id}}"},
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=200,
                    description="200 on user A's token accessing user B's resource = BOLA",
                    weight=1.0,
                ),
            ],
            severity_hint=Severity.CRITICAL,
            confidence_hint=0.9,
            requires_auth_context=requires_auth,
            requires_two_users=True,
        )

    def _build_from_llm(
        self, endpoint: Endpoint, suggestion, requires_auth: bool
    ) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"BOLA-llm-{suggestion.payload_description[:40]}",
            description=suggestion.payload_description,
            rationale=f"LLM-suggested: {suggestion.rationale}",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                body=suggestion.request_body or None,
                query_params=suggestion.query_params,
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=200,
                    description="200 on creative BOLA payload",
                    weight=0.7,
                ),
            ],
            severity_hint=Severity.HIGH,
            confidence_hint=0.5,
            requires_auth_context=requires_auth,
            metadata={"source": "llm"},
        )
