"""OWASP API7: Server-Side Request Forgery (SSRF) test generator."""

from core.api_security.generators.base import Generator
from core.api_security.models import APISpec, Endpoint, SchemaSpec
from core.api_security.test_models import (
    ExpectedIndicator,
    IndicatorType,
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)
from core.models import Severity

URL_PARAM_HINTS = {"url", "uri", "endpoint", "callback", "callback_url", "redirect", "redirect_uri",
                   "webhook", "webhook_url", "image_url", "fetch_url", "target", "next", "return_to",
                   "src", "source", "destination", "host", "proxy", "feed_url"}

# SSRF payloads — all hit non-routable / internal addresses, safe to send
SSRF_PAYLOADS = [
    ("http://127.0.0.1", "loopback IPv4"),
    ("http://localhost", "loopback hostname"),
    ("http://[::1]", "loopback IPv6"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://metadata.google.internal/", "GCP metadata"),
    ("file:///etc/passwd", "file:// scheme"),
    ("gopher://127.0.0.1:6379/_INFO", "gopher scheme"),
    ("http://0.0.0.0", "wildcard zero"),
    ("http://2130706433", "decimal-encoded 127.0.0.1"),
]


class SSRFGenerator(Generator):
    """API7: SSRF."""

    category = OWASPAPICategory.API7_SSRF
    name = "api7_ssrf"

    def generate(self, spec: APISpec) -> list[SecurityTest]:
        tests = []
        for endpoint in spec.endpoints:
            url_params = self._find_url_params(endpoint)
            if not url_params:
                continue
            for param_name, location in url_params:
                for payload, label in SSRF_PAYLOADS:
                    tests.append(self._build_test(endpoint, param_name, location, payload, label))
            if self.use_llm and self.llm_helper:
                for s in self.llm_helper.suggest_payloads(endpoint, self.category):
                    tests.append(self._build_from_llm(endpoint, s))
        return tests

    def _find_url_params(self, endpoint: Endpoint) -> list[tuple[str, str]]:
        """Return list of (param_name, location) for URL-accepting parameters."""
        found: list[tuple[str, str]] = []

        for param in endpoint.parameters:
            if self._is_url_like(param.name, getattr(param, "schema_spec", None)):
                found.append((param.name, param.location.value))

        if endpoint.request_body and endpoint.request_body.schema_spec:
            for prop_name, prop_schema in endpoint.request_body.schema_spec.properties.items():
                if self._is_url_like(prop_name, prop_schema):
                    found.append((prop_name, "body"))

        return found

    def _is_url_like(self, name: str, schema: SchemaSpec | None) -> bool:
        if name.lower() in URL_PARAM_HINTS:
            return True
        return bool(schema and schema.format in ("uri", "url"))

    def _build_test(
        self, endpoint: Endpoint, param_name: str, location: str, payload: str, label: str
    ) -> SecurityTest:
        body = None
        query = {}
        if location == "body":
            body = {param_name: payload}
        elif location == "query":
            query[param_name] = payload

        return SecurityTest(
            owasp_category=self.category,
            name=f"SSRF-{endpoint.operation_id or endpoint.path}-{param_name}-{label.replace(' ', '_')}",
            description=f"Set {param_name}={payload} ({label})",
            rationale=(
                f"Parameter '{param_name}' accepts URLs. Server may fetch this "
                "URL server-side, exposing internal services."
            ),
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                body=body,
                query_params=query,
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IS,
                    value=200,
                    description="200 + reflected internal response = SSRF confirmed",
                    weight=0.8,
                ),
                ExpectedIndicator(
                    type=IndicatorType.RESPONSE_TIME_GT,
                    value=3000,
                    description="Slow response = server attempted connection (timeout-based SSRF signal)",
                    weight=0.5,
                ),
                ExpectedIndicator(
                    type=IndicatorType.BODY_CONTAINS,
                    value="ami-id",
                    description="AWS metadata leak indicator",
                    weight=1.0,
                ),
            ],
            severity_hint=Severity.HIGH,
            confidence_hint=0.7,
        )

    def _build_from_llm(self, endpoint: Endpoint, suggestion) -> SecurityTest:
        return SecurityTest(
            owasp_category=self.category,
            name=f"SSRF-llm-{suggestion.payload_description[:40]}",
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
                    description="200 with LLM SSRF payload",
                    weight=0.6,
                ),
            ],
            severity_hint=Severity.HIGH,
            confidence_hint=0.5,
            metadata={"source": "llm"},
        )
