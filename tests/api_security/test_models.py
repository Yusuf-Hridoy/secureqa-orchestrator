"""Tests for the normalized APISpec model."""


from core.api_security.models import (
    APISpec,
    AuthSpec,
    AuthType,
    Endpoint,
    HTTPMethod,
    Parameter,
    ParameterLocation,
    SchemaSpec,
    SpecFormat,
)


def test_endpoint_basic_creation():
    """An endpoint with minimum fields is valid."""
    ep = Endpoint(path="/health", method=HTTPMethod.GET)
    assert ep.path == "/health"
    assert ep.method == HTTPMethod.GET
    assert ep.parameters == []


def test_endpoint_path_parameters_filter():
    """path_parameters() returns only PATH-location parameters."""
    ep = Endpoint(
        path="/users/{id}",
        method=HTTPMethod.GET,
        parameters=[
            Parameter(name="id", location=ParameterLocation.PATH, required=True),
            Parameter(name="filter", location=ParameterLocation.QUERY),
        ],
    )
    assert len(ep.path_parameters()) == 1
    assert ep.path_parameters()[0].name == "id"


def test_api_spec_endpoint_count():
    spec = APISpec(
        name="Test",
        source_format=SpecFormat.OPENAPI_3_0,
        endpoints=[
            Endpoint(path="/a", method=HTTPMethod.GET),
            Endpoint(path="/b", method=HTTPMethod.POST),
        ],
    )
    assert spec.endpoint_count() == 2


def test_api_spec_endpoints_by_method():
    spec = APISpec(
        name="Test",
        source_format=SpecFormat.OPENAPI_3_0,
        endpoints=[
            Endpoint(path="/a", method=HTTPMethod.GET),
            Endpoint(path="/b", method=HTTPMethod.POST),
            Endpoint(path="/c", method=HTTPMethod.GET),
        ],
    )
    assert len(spec.endpoints_by_method(HTTPMethod.GET)) == 2
    assert len(spec.endpoints_by_method(HTTPMethod.POST)) == 1


def test_schema_spec_recursive():
    """SchemaSpec can nest itself (object with property of type array of objects)."""
    schema = SchemaSpec(
        type="object",
        properties={
            "items": SchemaSpec(
                type="array",
                items=SchemaSpec(type="object"),
            ),
        },
    )
    assert schema.properties["items"].type == "array"
    assert schema.properties["items"].items.type == "object"


def test_authenticated_endpoints_filter():
    from core.api_security.models import SecurityRequirement
    spec = APISpec(
        name="Test",
        source_format=SpecFormat.OPENAPI_3_0,
        endpoints=[
            Endpoint(path="/public", method=HTTPMethod.GET),
            Endpoint(
                path="/private",
                method=HTTPMethod.GET,
                security=[SecurityRequirement(scheme_name="bearerAuth")],
            ),
        ],
    )
    assert len(spec.authenticated_endpoints()) == 1
    assert spec.authenticated_endpoints()[0].path == "/private"
    assert len(spec.unauthenticated_endpoints()) == 1


def test_auth_spec_defaults():
    auth = AuthSpec()
    assert auth.type == AuthType.NONE
    assert auth.location is None


def test_http_method_enum_values():
    assert HTTPMethod.GET.value == "GET"
    assert HTTPMethod.DELETE.value == "DELETE"
    # str-based enum: comparison with string works
    assert HTTPMethod.GET == "GET"
