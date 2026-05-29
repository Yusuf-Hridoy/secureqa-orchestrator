"""Normalized internal model for parsed API specifications.

All parsers (OpenAPI 3.0, OpenAPI 3.1, Postman v2.1) produce an APISpec.
All downstream code (test generators, runner, classifier) consumes APISpec only.
This is the abstraction layer that decouples input formats from scan logic.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ---------- Enums ----------


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParameterLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"


class AuthType(str, Enum):
    NONE = "none"
    API_KEY = "api_key"
    BEARER = "bearer"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    UNKNOWN = "unknown"


class SpecFormat(str, Enum):
    OPENAPI_3_0 = "openapi_3_0"
    OPENAPI_3_1 = "openapi_3_1"
    POSTMAN_2_1 = "postman_2_1"


# ---------- Schema (lightweight type model) ----------


class SchemaSpec(BaseModel):
    """A JSON Schema-like type descriptor. Kept lightweight — full validation isn't our job."""

    type: str | None = None  # "string", "integer", "object", "array", etc.
    format: str | None = None  # "int32", "email", "uuid", etc.
    enum: list[Any] | None = None
    properties: dict[str, "SchemaSpec"] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)
    items: "SchemaSpec | None" = None
    example: Any | None = None
    description: str | None = None
    nullable: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)  # original spec dict for full fidelity


# ---------- Auth ----------


class AuthSpec(BaseModel):
    """How the API authenticates."""

    type: AuthType = AuthType.NONE
    location: str | None = None  # "header", "query" (for api_key)
    name: str | None = None  # header name or query param name
    scheme: str | None = None  # "bearer", "basic"
    bearer_format: str | None = None  # "JWT"
    flows: dict[str, Any] = Field(default_factory=dict)  # OAuth2 flows
    description: str | None = None


# ---------- Parameter ----------


class Parameter(BaseModel):
    """A single parameter (path, query, header, or cookie)."""

    name: str
    location: ParameterLocation
    required: bool = False
    schema_spec: SchemaSpec = Field(default_factory=SchemaSpec, alias="schema")
    example: Any | None = None
    description: str | None = None

    model_config = {"populate_by_name": True}


# ---------- Request body / Response ----------


class RequestBody(BaseModel):
    """Body of a request (for POST, PUT, PATCH)."""

    required: bool = False
    content_type: str = "application/json"
    schema_spec: SchemaSpec = Field(default_factory=SchemaSpec, alias="schema")
    example: Any | None = None

    model_config = {"populate_by_name": True}


class Response(BaseModel):
    """A single response definition (one per status code)."""

    status_code: str  # "200", "default", "4XX", etc.
    description: str = ""
    content_type: str | None = None
    schema_spec: SchemaSpec | None = Field(default=None, alias="schema")

    model_config = {"populate_by_name": True}


class SecurityRequirement(BaseModel):
    """Reference to a security scheme used by an endpoint."""

    scheme_name: str  # references AuthSpec by name
    scopes: list[str] = Field(default_factory=list)


# ---------- Endpoint ----------


class Endpoint(BaseModel):
    """A single API endpoint (path + method combination)."""

    path: str  # e.g., "/users/{id}"
    method: HTTPMethod
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    request_body: RequestBody | None = None
    responses: dict[str, Response] = Field(default_factory=dict)
    security: list[SecurityRequirement] = Field(default_factory=list)
    deprecated: bool = False
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    has_partial_spec: bool = False  # True if external $refs were skipped

    def path_parameters(self) -> list[Parameter]:
        """Return only path parameters."""
        return [p for p in self.parameters if p.location == ParameterLocation.PATH]

    def query_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == ParameterLocation.QUERY]

    def header_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == ParameterLocation.HEADER]


# ---------- Top-level spec ----------


class ParseWarning(BaseModel):
    """A non-fatal warning produced during parsing."""

    code: str  # e.g., "EXTERNAL_REF_SKIPPED", "MISSING_OPERATION_ID"
    message: str
    location: str | None = None  # path in the spec where warning occurred


class APISpec(BaseModel):
    """Normalized internal representation of an API spec."""

    name: str
    version: str = "unknown"
    description: str | None = None
    source_format: SpecFormat
    base_url: str = ""  # may be empty if not specified
    servers: list[str] = Field(default_factory=list)  # additional server URLs
    auth_schemes: dict[str, AuthSpec] = Field(default_factory=dict)  # name → spec
    endpoints: list[Endpoint] = Field(default_factory=list)
    warnings: list[ParseWarning] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def endpoint_count(self) -> int:
        return len(self.endpoints)

    def endpoints_by_method(self, method: HTTPMethod) -> list[Endpoint]:
        return [e for e in self.endpoints if e.method == method]

    def authenticated_endpoints(self) -> list[Endpoint]:
        """Return endpoints that require authentication."""
        return [e for e in self.endpoints if e.security]

    def unauthenticated_endpoints(self) -> list[Endpoint]:
        return [e for e in self.endpoints if not e.security]


# Resolve forward references (SchemaSpec is recursive)
SchemaSpec.model_rebuild()
