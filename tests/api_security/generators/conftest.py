"""Shared fixtures for generator tests."""

import pytest

from core.api_security.models import (
    APISpec,
    AuthSpec,
    AuthType,
    Endpoint,
    HTTPMethod,
    Parameter,
    ParameterLocation,
    RequestBody,
    Response,
    SchemaSpec,
    SecurityRequirement,
    SpecFormat,
)


@pytest.fixture
def simple_api_spec() -> APISpec:
    """A minimal APISpec with one GET endpoint and one POST endpoint."""
    return APISpec(
        name="Test API",
        version="1.0",
        source_format=SpecFormat.OPENAPI_3_0,
        base_url="https://api.staging.example.com",
        auth_schemes={
            "bearerAuth": AuthSpec(type=AuthType.BEARER, scheme="bearer"),
        },
        endpoints=[
            Endpoint(
                path="/users/{userId}",
                method=HTTPMethod.GET,
                operation_id="getUser",
                parameters=[
                    Parameter(
                        name="userId",
                        location=ParameterLocation.PATH,
                        required=True,
                    )
                ],
                responses={
                    "200": Response(status_code="200", description="OK"),
                },
                security=[SecurityRequirement(scheme_name="bearerAuth")],
            ),
            Endpoint(
                path="/users",
                method=HTTPMethod.POST,
                operation_id="createUser",
                request_body=RequestBody(
                    required=True,
                    content_type="application/json",
                    schema=SchemaSpec(
                        type="object",
                        properties={
                            "name": SchemaSpec(type="string"),
                            "email": SchemaSpec(type="string", format="email"),
                            "is_admin": SchemaSpec(type="boolean"),
                        },
                        required=["name", "email"],
                    ),
                ),
                responses={
                    "201": Response(status_code="201", description="Created"),
                },
            ),
        ],
    )


@pytest.fixture
def empty_api_spec() -> APISpec:
    """An APISpec with no endpoints."""
    return APISpec(
        name="Empty",
        source_format=SpecFormat.OPENAPI_3_0,
        endpoints=[],
    )


@pytest.fixture
def admin_endpoint_spec() -> APISpec:
    """APISpec with endpoints that look admin-only (for API5 tests)."""
    return APISpec(
        name="Admin API",
        source_format=SpecFormat.OPENAPI_3_0,
        base_url="https://api.staging.example.com",
        endpoints=[
            Endpoint(
                path="/admin/users",
                method=HTTPMethod.GET,
                operation_id="adminListUsers",
                responses={"200": Response(status_code="200")},
                tags=["admin"],
            ),
            Endpoint(
                path="/users/{id}/delete",
                method=HTTPMethod.DELETE,
                operation_id="deleteUser",
                parameters=[
                    Parameter(name="id", location=ParameterLocation.PATH, required=True)
                ],
                responses={"204": Response(status_code="204")},
            ),
            Endpoint(
                path="/users/me",
                method=HTTPMethod.GET,
                operation_id="getMyProfile",
                responses={"200": Response(status_code="200")},
            ),
        ],
    )


@pytest.fixture
def ssrf_candidate_spec() -> APISpec:
    """APISpec with parameters that accept URLs (SSRF candidates)."""
    return APISpec(
        name="SSRF Target API",
        source_format=SpecFormat.OPENAPI_3_0,
        base_url="https://api.staging.example.com",
        endpoints=[
            Endpoint(
                path="/fetch",
                method=HTTPMethod.POST,
                operation_id="fetchUrl",
                request_body=RequestBody(
                    content_type="application/json",
                    schema=SchemaSpec(
                        type="object",
                        properties={
                            "url": SchemaSpec(type="string", format="uri"),
                            "callback_url": SchemaSpec(type="string"),
                        },
                    ),
                ),
                responses={"200": Response(status_code="200")},
            ),
        ],
    )
