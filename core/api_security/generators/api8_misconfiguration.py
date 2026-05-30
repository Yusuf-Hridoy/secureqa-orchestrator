"""OWASP API8: Security Misconfiguration test generator."""

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

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — enforces HTTPS",
    "X-Content-Type-Options": "Prevents MIME-sniffing",
    "X-Frame-Options": "Clickjacking protection",
    "Content-Security-Policy": "XSS / injection mitigation",
    "Referrer-Policy": "Controls referrer leakage",
    "Permissions-Policy": "Restricts browser features",
}


class MisconfigurationGenerator(Generator):
    """API8: Security Misconfiguration."""

    category = OWASPAPICategory.API8_MISCONFIGURATION
    name = "api8_misconfiguration"

    def generate(self, spec: APISpec) -> list[SecurityTest]:
        tests = []
        # Per-spec checks: only one set of header tests is needed (spec-level),
        # but we generate them against the first endpoint for execution context.
        if not spec.endpoints:
            return tests

        anchor = spec.endpoints[0]
        for header, description in REQUIRED_SECURITY_HEADERS.items():
            tests.append(self._header_missing_test(anchor, header, description))

        # Verbose error trigger: send malformed JSON to body endpoints
        for endpoint in spec.endpoints:
            if endpoint.request_body is not None:
                tests.append(self._verbose_error_test(endpoint))
                break  # one is enough — spec-level check

        return tests

    def _header_missing_test(self, endpoint: Endpoint, header: str, description: str) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"MISC-header-missing-{header}",
            description=f"Check response is missing {header}",
            rationale=f"{description}. Missing this header weakens browser-side defenses.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(method=endpoint.method, path=endpoint.path),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.HEADER_MISSING,
                    value=None,
                    target=header,
                    description=f"{header} not set in response",
                    weight=1.0,
                ),
            ],
            severity_hint=Severity.MEDIUM,
            confidence_hint=0.95,
        )

    def _verbose_error_test(self, endpoint: Endpoint) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"MISC-verbose-error-{endpoint.operation_id or endpoint.path}",
            description="Send malformed JSON to trigger error",
            rationale="Verbose error messages can leak stack traces, framework versions, DB info.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                body="{ this is not valid json",
                content_type="application/json",
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.BODY_CONTAINS,
                    value="Traceback",
                    description="Python traceback in response = info disclosure",
                    weight=1.0,
                ),
                ExpectedIndicator(
                    type=IndicatorType.BODY_CONTAINS,
                    value="at java.",
                    description="Java stack trace in response = info disclosure",
                    weight=1.0,
                ),
                ExpectedIndicator(
                    type=IndicatorType.BODY_CONTAINS,
                    value="SQLException",
                    description="SQL error in response = info disclosure",
                    weight=1.0,
                ),
            ],
            severity_hint=Severity.MEDIUM,
            confidence_hint=0.85,
        )
