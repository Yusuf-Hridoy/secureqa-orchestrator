"""Models for planned security tests (the output of Phase 1B generators).

A SecurityTest is a PLAN, not a result. Phase 1C executes it and produces Findings.
"""

from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from core.api_security.models import HTTPMethod
from core.models import Severity


class OWASPAPICategory(str, Enum):
    """OWASP API Security Top 10 (2023) categories."""

    API1_BOLA = "API1_BOLA"
    API2_BROKEN_AUTH = "API2_BROKEN_AUTH"
    API3_PROPERTY_AUTH = "API3_PROPERTY_AUTH"
    API4_RESOURCE_CONSUMPTION = "API4_RESOURCE_CONSUMPTION"
    API5_FUNCTION_AUTH = "API5_FUNCTION_AUTH"
    API6_BUSINESS_FLOWS = "API6_BUSINESS_FLOWS"  # Not implemented in Phase 1
    API7_SSRF = "API7_SSRF"
    API8_MISCONFIGURATION = "API8_MISCONFIGURATION"
    API9_INVENTORY = "API9_INVENTORY"
    API10_THIRD_PARTY = "API10_THIRD_PARTY"  # Not implemented in Phase 1


class IndicatorType(str, Enum):
    """How to interpret a response to detect a vulnerability."""

    STATUS_CODE_IS = "status_code_is"  # response status equals value
    STATUS_CODE_IN = "status_code_in"  # response status in list
    STATUS_CODE_NOT = "status_code_not"  # response status NOT equals value
    HEADER_MISSING = "header_missing"  # named header absent
    HEADER_PRESENT = "header_present"  # named header present
    HEADER_VALUE_IS = "header_value_is"  # header value matches
    BODY_CONTAINS = "body_contains"  # response body contains substring
    BODY_NOT_CONTAINS = "body_not_contains"  # response body MUST NOT contain substring
    BODY_MATCHES_REGEX = "body_matches_regex"  # regex match
    RESPONSE_TIME_GT = "response_time_gt"  # latency > N ms
    RESPONSE_SIZE_GT = "response_size_gt"  # body bytes > N


class ExpectedIndicator(BaseModel):
    """A single check applied to the response."""

    type: IndicatorType
    value: Any = None  # the value to compare against (status code, header name, regex, etc.)
    target: str | None = None  # for header indicators: header name; for body: optional
    description: str = ""  # human-readable explanation
    weight: float = Field(default=1.0, ge=0.0, le=1.0)  # how strongly this indicator suggests a vuln


class TestPayload(BaseModel):
    """Concrete request data for a SecurityTest."""

    __test__ = False  # prevent pytest collection

    method: HTTPMethod
    path: str  # may contain {placeholders}
    path_params: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] | str | None = None
    content_type: str = "application/json"


class SecurityTest(BaseModel):
    """A planned security test. Phase 1C will execute it."""

    test_id: str = Field(default_factory=lambda: str(uuid4()))
    owasp_category: OWASPAPICategory
    name: str  # short label, e.g. "BOLA-id-substitution-0"
    description: str  # what this test checks
    rationale: str  # WHY this test was generated for this endpoint
    target_endpoint_path: str  # original endpoint path
    target_endpoint_method: HTTPMethod
    payload: TestPayload
    indicators: list[ExpectedIndicator] = Field(default_factory=list)
    severity_hint: Severity = Severity.MEDIUM  # generator's guess at severity
    confidence_hint: float = Field(default=0.6, ge=0.0, le=1.0)  # generator's confidence
    requires_auth_context: bool = False  # True if test needs a valid user token
    requires_two_users: bool = False  # True if BOLA needs userA + userB tokens
    metadata: dict[str, Any] = Field(default_factory=dict)
