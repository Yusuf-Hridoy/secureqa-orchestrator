"""OWASP API3: Broken Object Property Authorization (Mass Assignment)."""

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

# Sensitive fields that should normally NOT be accepted from clients
SENSITIVE_FIELDS = {
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "role": "admin",
    "roles": ["admin", "superuser"],
    "user_id": 1,
    "userId": 1,
    "account_balance": 999999,
    "balance": 999999,
    "verified": True,
    "is_verified": True,
    "email_verified": True,
    "is_premium": True,
    "subscription_tier": "enterprise",
    "permissions": ["*"],
    "owner_id": 1,
    "tenant_id": 1,
}

BODY_METHODS = {HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH}


class PropertyAuthGenerator(Generator):
    """API3: Mass Assignment / Broken Object Property Authorization."""

    category = OWASPAPICategory.API3_PROPERTY_AUTH
    name = "api3_property_auth"

    def generate(self, spec: APISpec) -> list[SecurityTest]:
        tests: list[SecurityTest] = []
        for endpoint in spec.endpoints:
            if endpoint.method not in BODY_METHODS:
                continue
            if endpoint.request_body is None:
                continue
            tests.extend(self._tests_for_endpoint(endpoint))
            if self.use_llm and self.llm_helper:
                for s in self.llm_helper.suggest_payloads(endpoint, self.category):
                    tests.append(self._build_from_llm(endpoint, s))
        return tests

    def _tests_for_endpoint(self, endpoint: Endpoint) -> list[SecurityTest]:
        tests = []
        # Build base body from schema example or empty
        base_body = self._base_body(endpoint)

        # One test per sensitive field
        for field, value in SENSITIVE_FIELDS.items():
            body = dict(base_body)
            body[field] = value
            tests.append(
                SecurityTest(
                    owasp_category=self.category,
                    name=f"MASS-ASSIGN-{endpoint.operation_id or endpoint.path}-{field}",
                    description=f"Inject '{field}={value!r}' into request body",
                    rationale=(
                        f"Field '{field}' is typically server-controlled. If the API "
                        "accepts it from the client, privilege escalation may be possible."
                    ),
                    target_endpoint_path=endpoint.path,
                    target_endpoint_method=endpoint.method,
                    payload=TestPayload(
                        method=endpoint.method,
                        path=endpoint.path,
                        body=body,
                        content_type=endpoint.request_body.content_type if endpoint.request_body else "application/json",
                    ),
                    indicators=[
                        ExpectedIndicator(
                            type=IndicatorType.STATUS_CODE_IN,
                            value=[200, 201, 204],
                            description=(
                                f"Success status with injected '{field}' suggests the "
                                "field was accepted (verify in response body or DB)."
                            ),
                            weight=0.7,
                        ),
                        ExpectedIndicator(
                            type=IndicatorType.BODY_CONTAINS,
                            value=field,
                            description=(
                                f"Response echoes '{field}' — strong signal it was accepted."
                            ),
                            weight=0.9,
                        ),
                    ],
                    severity_hint=Severity.HIGH,
                    confidence_hint=0.6,
                )
            )
        return tests

    def _base_body(self, endpoint: Endpoint) -> dict:
        """Build a minimal valid body from the endpoint schema."""
        if not endpoint.request_body:
            return {}
        schema = endpoint.request_body.schema_spec
        if schema.example and isinstance(schema.example, dict):
            return dict(schema.example)
        # Fall back to filling required fields with stub values
        body = {}
        for required_field in schema.required:
            prop = schema.properties.get(required_field)
            body[required_field] = self._stub_value(prop)
        return body

    def _stub_value(self, schema) -> object:
        if schema is None:
            return "test"
        if schema.type == "string":
            if schema.format == "email":
                return "test@example.com"
            if schema.format == "uri":
                return "https://example.com"
            if schema.format == "uuid":
                return "00000000-0000-0000-0000-000000000000"
            return "test"
        if schema.type == "integer":
            return 1
        if schema.type == "number":
            return 1.0
        if schema.type == "boolean":
            return False
        if schema.type == "array":
            return []
        if schema.type == "object":
            return {}
        return "test"

    def _build_from_llm(self, endpoint, suggestion):
        return SecurityTest(
            owasp_category=self.category,
            name=f"MASS-ASSIGN-llm-{suggestion.payload_description[:40]}",
            description=suggestion.payload_description,
            rationale=f"LLM-suggested: {suggestion.rationale}",
            target_endpoint_path=endpoint.path,
            target_endpoint_method=endpoint.method,
            payload=TestPayload(
                method=endpoint.method,
                path=endpoint.path,
                body=suggestion.request_body or {},
            ),
            indicators=[
                ExpectedIndicator(
                    type=IndicatorType.STATUS_CODE_IN,
                    value=[200, 201, 204],
                    description="Success with LLM-crafted mass assignment payload",
                    weight=0.7,
                ),
            ],
            severity_hint=Severity.HIGH,
            confidence_hint=0.5,
            metadata={"source": "llm"},
        )
