"""OWASP API2: Broken Authentication test generator."""

from core.api_security.generators.base import Generator
from core.api_security.models import APISpec, AuthType, Endpoint
from core.api_security.test_models import (
    ExpectedIndicator,
    IndicatorType,
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)
from core.models import Severity

# Test tokens — clearly fake, safe for testing
EXPIRED_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ."
    "ftnvqA1ZpDgRX-7Pe6kbW0aYS5h0LnSGqj-J7CRZ_QU"
)
# alg=none JWT: header { "alg": "none", "typ": "JWT" }, body { "sub": "admin" }
ALG_NONE_JWT = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJzdWIiOiJhZG1pbiJ9."
)


class BrokenAuthGenerator(Generator):
    """API2: Broken Authentication."""

    category = OWASPAPICategory.API2_BROKEN_AUTH
    name = "api2_broken_auth"

    def generate(self, spec: APISpec) -> list[SecurityTest]:
        tests: list[SecurityTest] = []

        for endpoint in spec.endpoints:
            if not endpoint.security:
                continue  # no auth needed → not a target for this category

            # Detect auth scheme
            scheme_name = endpoint.security[0].scheme_name
            scheme = spec.auth_schemes.get(scheme_name)
            auth_type = scheme.type if scheme else AuthType.UNKNOWN

            tests.append(self._test_no_auth(endpoint))
            tests.append(self._test_empty_bearer(endpoint))
            tests.append(self._test_malformed_jwt(endpoint))
            tests.append(self._test_expired_jwt(endpoint))
            tests.append(self._test_alg_none(endpoint))

            if auth_type == AuthType.BEARER:
                tests.append(self._test_wrong_scheme(endpoint))

            if self.use_llm and self.llm_helper:
                for s in self.llm_helper.suggest_payloads(endpoint, self.category):
                    tests.append(self._build_from_llm(endpoint, s))

        return tests

    def _base_payload(self, endpoint: Endpoint, headers: dict[str, str]) -> TestPayload:
        return TestPayload(
            method=endpoint.method,
            path=endpoint.path,
            headers=headers,
        )

    def _expect_unauthorized(self, weight: float = 1.0) -> ExpectedIndicator:
        return ExpectedIndicator(
            type=IndicatorType.STATUS_CODE_IN,
            value=[401, 403],
            description="Endpoint MUST return 401 or 403 on bad/missing auth",
            weight=weight,
        )

    def _expect_not_success(self, weight: float = 0.9) -> ExpectedIndicator:
        return ExpectedIndicator(
            type=IndicatorType.STATUS_CODE_NOT,
            value=200,
            description="200 OK without valid auth = broken auth",
            weight=weight,
        )

    def _test_no_auth(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"AUTH-no-token-{endpoint.operation_id or endpoint.path}",
            description="Request endpoint with no Authorization header",
            rationale="Endpoint requires auth; missing token must be rejected.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=self._base_payload(endpoint, {}),
            indicators=[self._expect_unauthorized(), self._expect_not_success()],
            severity_hint=Severity.CRITICAL,
            confidence_hint=0.95,
            requires_auth_context=False,
        )

    def _test_empty_bearer(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"AUTH-empty-bearer-{endpoint.operation_id or endpoint.path}",
            description="Send empty Bearer token",
            rationale="Empty bearer must be rejected like missing token.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=self._base_payload(endpoint, {"Authorization": "Bearer "}),
            indicators=[self._expect_unauthorized()],
            severity_hint=Severity.HIGH,
            confidence_hint=0.9,
        )

    def _test_malformed_jwt(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"AUTH-malformed-jwt-{endpoint.operation_id or endpoint.path}",
            description="Send a malformed JWT",
            rationale="Malformed tokens must be rejected.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=self._base_payload(endpoint, {"Authorization": "Bearer not.a.jwt"}),
            indicators=[self._expect_unauthorized()],
            severity_hint=Severity.MEDIUM,
            confidence_hint=0.85,
        )

    def _test_expired_jwt(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"AUTH-expired-jwt-{endpoint.operation_id or endpoint.path}",
            description="Send an expired JWT",
            rationale="Expired tokens must be rejected.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=self._base_payload(endpoint, {"Authorization": f"Bearer {EXPIRED_JWT}"}),
            indicators=[self._expect_unauthorized()],
            severity_hint=Severity.HIGH,
            confidence_hint=0.85,
        )

    def _test_alg_none(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"AUTH-alg-none-{endpoint.operation_id or endpoint.path}",
            description="Send a JWT with alg=none",
            rationale=(
                "Classic JWT vulnerability: some libraries accept alg=none, allowing "
                "attackers to forge tokens."
            ),
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=self._base_payload(endpoint, {"Authorization": f"Bearer {ALG_NONE_JWT}"}),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=200,
                    description="200 with alg=none JWT = critical auth bypass",
                    weight=1.0,
                ),
            ],
            severity_hint=Severity.CRITICAL,
            confidence_hint=0.9,
        )

    def _test_wrong_scheme(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"AUTH-wrong-scheme-{endpoint.operation_id or endpoint.path}",
            description="Send Basic auth on a Bearer endpoint",
            rationale="Server should reject wrong-scheme auth.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=self._base_payload(endpoint, {"Authorization": "Basic dGVzdDp0ZXN0"}),
            indicators=[self._expect_unauthorized()],
            severity_hint=Severity.LOW,
            confidence_hint=0.6,
        )

    def _build_from_llm(self, endpoint: Endpoint, suggestion) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"AUTH-llm-{suggestion.payload_description[:40]}",
            description=suggestion.payload_description,
            rationale=f"LLM-suggested: {suggestion.rationale}",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                headers={},
                body=suggestion.request_body or None,
            ),
            indicators=[self._expect_unauthorized(weight=0.7)],
            severity_hint=Severity.HIGH,
            confidence_hint=0.5,
            metadata={"source": "llm"},
        )
