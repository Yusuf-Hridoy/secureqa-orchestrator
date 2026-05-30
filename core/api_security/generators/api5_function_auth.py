"""OWASP API5: Broken Function-Level Authorization (soft implementation).

We don't have a role matrix in v1, so this generator flags endpoints that LOOK
admin-only based on path and method, plus tests that attempt access without
elevated context.
"""

import re

from core.api_security.generators.base import Generator
from core.api_security.models import APISpec, Endpoint, HTTPMethod
from core.api_security.test_models import (
    ExpectedIndicator,
    IndicatorType,
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)
from core.models import Severity

ADMIN_INDICATORS = [
    re.compile(r"/admin\b", re.IGNORECASE),
    re.compile(r"/internal\b", re.IGNORECASE),
    re.compile(r"/manage\b", re.IGNORECASE),
    re.compile(r"/dashboard\b", re.IGNORECASE),
    re.compile(r"/staff\b", re.IGNORECASE),
    re.compile(r"/superuser\b", re.IGNORECASE),
]

ADMIN_TAGS = {"admin", "internal", "management", "staff"}


class FunctionLevelAuthGenerator(Generator):
    """API5 (soft): Function-Level Authorization."""

    category = OWASPAPICategory.API5_FUNCTION_AUTH
    name = "api5_function_auth"

    def generate(self, spec: APISpec) -> list[SecurityTest]:
        tests = []
        for endpoint in spec.endpoints:
            if not self._is_admin_endpoint(endpoint):
                continue

            tests.append(self._unauthenticated_access(endpoint))
            tests.append(self._regular_user_access(endpoint))

            # DELETE on user resources (privileged op)
            if endpoint.method == HTTPMethod.DELETE:
                tests.append(self._privileged_delete(endpoint))
        return tests

    def _is_admin_endpoint(self, endpoint: Endpoint) -> bool:
        if any(pattern.search(endpoint.path) for pattern in ADMIN_INDICATORS):
            return True
        if any(tag.lower() in ADMIN_TAGS for tag in endpoint.tags):
            return True
        # DELETE on /users/{...} pattern likely admin-ish
        return endpoint.method == HTTPMethod.DELETE and "/users" in endpoint.path

    def _unauthenticated_access(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"FLA-unauth-{endpoint.operation_id or endpoint.path}",
            description="Access admin-looking endpoint with no auth",
            rationale=(
                f"Endpoint {endpoint.path} appears admin-only. "
                "Unauthenticated access must be rejected."
            ),
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(method=endpoint.method, path=endpoint.path),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IN,
                    value=[401, 403],
                    description="Must reject unauthenticated access",
                    weight=1.0,
                ),
            ],
            severity_hint=Severity.HIGH,
            confidence_hint=0.8,
        )

    def _regular_user_access(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"FLA-regular-user-{endpoint.operation_id or endpoint.path}",
            description="Access admin-looking endpoint with regular user token",
            rationale="Regular users should not be able to hit admin-only endpoints.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                headers={"Authorization": "Bearer {{regular_user_token}}"},
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=403,
                    description="403 expected for regular user on admin endpoint",
                    weight=0.9,
                ),
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=200,
                    description="200 = regular user got admin access = critical",
                    weight=1.0,
                ),
            ],
            severity_hint=Severity.CRITICAL,
            confidence_hint=0.7,
            requires_auth_context=True,
        )

    def _privileged_delete(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"FLA-delete-{endpoint.operation_id or endpoint.path}",
            description=f"Attempt DELETE {endpoint.path} as regular user",
            rationale="DELETE operations on user resources need elevated auth.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                headers={"Authorization": "Bearer {{regular_user_token}}"},
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IN,
                    value=[403, 401],
                    description="Should require elevated auth",
                    weight=0.9,
                ),
            ],
            severity_hint=Severity.HIGH,
            confidence_hint=0.6,
            requires_auth_context=True,
        )
