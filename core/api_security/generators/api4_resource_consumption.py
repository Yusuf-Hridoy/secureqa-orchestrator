"""OWASP API4: Unrestricted Resource Consumption."""

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

PAGINATION_PARAM_NAMES = {"limit", "size", "per_page", "perPage", "pageSize", "count", "max"}


class ResourceConsumptionGenerator(Generator):
    """API4: Unrestricted Resource Consumption."""

    category = OWASPAPICategory.API4_RESOURCE_CONSUMPTION
    name = "api4_resource_consumption"

    def generate(self, spec: APISpec) -> list[SecurityTest]:
        tests = []
        for endpoint in spec.endpoints:
            # Pagination abuse on query params with known names
            for param in endpoint.query_parameters():
                if param.name in PAGINATION_PARAM_NAMES:
                    tests.append(self._oversized_pagination(endpoint, param.name))
                    tests.append(self._negative_pagination(endpoint, param.name))

            # Deep nesting payload for body endpoints
            if endpoint.request_body is not None:
                tests.append(self._deep_nesting(endpoint))
        return tests

    def _oversized_pagination(self, endpoint: Endpoint, param_name: str) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"RC-oversized-{param_name}-{endpoint.operation_id or endpoint.path}",
            description=f"Set {param_name}=1000000",
            rationale=(
                f"Pagination param '{param_name}' with extreme value may cause "
                "DB-level resource exhaustion or unbounded response."
            ),
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                query_params={param_name: "1000000"},
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=200,
                    description="200 with oversized pagination = no upper bound enforced",
                    weight=0.7,
                ),
                ExpectedIndicator(
                    type=IndicatorType.RESPONSE_TIME_GT,
                    value=5000,
                    description="Slow response suggests no efficient pagination",
                    weight=0.6,
                ),
            ],
            severity_hint=Severity.MEDIUM,
            confidence_hint=0.7,
        )

    def _negative_pagination(self, endpoint: Endpoint, param_name: str) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"RC-negative-{param_name}-{endpoint.operation_id or endpoint.path}",
            description=f"Set {param_name}=-1",
            rationale="Negative pagination may bypass limits or trigger errors.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                query_params={param_name: "-1"},
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=500,
                    description="500 on negative pagination = poor input validation",
                    weight=0.7,
                ),
            ],
            severity_hint=Severity.LOW,
            confidence_hint=0.6,
        )

    def _deep_nesting(self, endpoint: Endpoint) -> SecurityTest:
        # Build a 50-deep nested object
        body: dict = {"x": {}}
        cur = body["x"]
        for _ in range(50):
            cur["x"] = {}
            cur = cur["x"]
        return SecurityTest(
            owasp_category=self.category,
            name=f"RC-deep-nesting-{endpoint.operation_id or endpoint.path}",
            description="Send a 50-deep nested JSON payload",
            rationale="Deep nesting can cause stack overflow or DoS in poorly-bounded parsers.",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                body=body,
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=500,
                    description="500 = parser couldn't handle nesting",
                    weight=0.8,
                ),
            ],
            severity_hint=Severity.MEDIUM,
            confidence_hint=0.6,
        )
