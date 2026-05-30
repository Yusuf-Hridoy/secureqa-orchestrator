"""OWASP API9: Improper Inventory Management test generator."""

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

# Common debug / hidden endpoint paths to probe
COMMON_HIDDEN_PATHS = [
    "/.env",
    "/.git/config",
    "/debug",
    "/debug/vars",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/admin",
    "/console",
    "/phpinfo.php",
    "/server-status",
    "/healthz",
    "/metrics",
]


class InventoryGenerator(Generator):
    """API9: Improper Inventory Management."""

    category = OWASPAPICategory.API9_INVENTORY
    name = "api9_inventory"

    def generate(self, spec: APISpec) -> list[SecurityTest]:
        tests = []
        documented_paths = {e.path for e in spec.endpoints}

        # Probe common hidden paths
        for path in COMMON_HIDDEN_PATHS:
            if path in documented_paths:
                continue  # don't double-test documented endpoints
            tests.append(self._hidden_path_test(path))

        # Wrong-method test for each endpoint (if method is GET, try POST/DELETE etc.)
        for endpoint in spec.endpoints:
            for alt_method in self._alternative_methods(endpoint.method):
                tests.append(self._wrong_method_test(endpoint, alt_method))

        return tests

    def _alternative_methods(self, method: HTTPMethod) -> list[HTTPMethod]:
        """Return safe alt methods to try."""
        if method == HTTPMethod.GET:
            return [HTTPMethod.OPTIONS, HTTPMethod.HEAD]
        if method == HTTPMethod.POST:
            return [HTTPMethod.OPTIONS]
        return [HTTPMethod.OPTIONS]

    def _hidden_path_test(self, path: str) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"INV-hidden-path-{path}",
            description=f"Probe undocumented path {path}",
            rationale=(
                f"{path} is a common debug/admin path. If exposed, it may leak "
                "config, source, or internal state."
            ),
            target_endpoint_path=path,
            target_endpoint_method=HTTPMethod.GET,
            payload=TestPayload(method=HTTPMethod.GET, path=path),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=200,
                    description="200 on undocumented debug path = exposure",
                    weight=1.0,
                ),
            ],
            severity_hint=Severity.MEDIUM,
            confidence_hint=0.8,
        )

    def _wrong_method_test(self, endpoint: Endpoint, alt_method: HTTPMethod) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"INV-alt-method-{alt_method.value}-{endpoint.operation_id or endpoint.path}",
            description=f"Try {alt_method.value} on {endpoint.path}",
            rationale=(
                "Unexpected methods on documented endpoints may reveal hidden "
                "functionality or method-confusion bugs."
            ),
            target_endpoint_path=endpoint.path,
            target_endpoint_method=alt_method,
            payload=TestPayload(method=alt_method, path=endpoint.path),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_NOT,
                    value=405,
                    description="405 expected for unsupported method; anything else may be an info leak",
                    weight=0.6,
                ),
            ],
            severity_hint=Severity.LOW,
            confidence_hint=0.5,
        )
