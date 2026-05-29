"""Tests for the OpenAPI parser."""

import json
from pathlib import Path

import pytest

from core.api_security.exceptions import SpecParseError, UnsupportedSpecError
from core.api_security.models import (
    AuthType,
    HTTPMethod,
    SpecFormat,
)
from core.api_security.parsers.openapi_parser import OpenAPIParser

FIXTURES = Path("tests/fixtures/specs")


@pytest.fixture
def petstore_3_0():
    return json.loads((FIXTURES / "petstore_openapi_3_0.json").read_text())


@pytest.fixture
def petstore_3_1_yaml():
    return (FIXTURES / "petstore_openapi_3_1.yaml").read_text()


@pytest.fixture
def minimal_spec():
    return json.loads((FIXTURES / "minimal_openapi.json").read_text())


@pytest.fixture
def malformed_spec():
    return json.loads((FIXTURES / "malformed_openapi.json").read_text())


def test_can_parse_openapi_3_0(petstore_3_0):
    parser = OpenAPIParser()
    assert parser.can_parse(petstore_3_0)


def test_can_parse_openapi_3_1_yaml_string(petstore_3_1_yaml):
    parser = OpenAPIParser()
    assert parser.can_parse(petstore_3_1_yaml)


def test_cannot_parse_postman_collection():
    parser = OpenAPIParser()
    postman = {
        "info": {
            "name": "X",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        }
    }
    assert parser.can_parse(postman) is False


def test_parse_petstore_basic_metadata(petstore_3_0):
    parser = OpenAPIParser()
    spec = parser.parse(petstore_3_0)
    assert spec.name == "Petstore"
    assert spec.version == "1.0.0"
    assert spec.source_format == SpecFormat.OPENAPI_3_0
    assert spec.base_url == "https://petstore.example.com/api/v1"


def test_parse_petstore_endpoints_count(petstore_3_0):
    parser = OpenAPIParser()
    spec = parser.parse(petstore_3_0)
    # /pets GET, POST; /pets/{petId} GET, DELETE = 4 endpoints
    assert spec.endpoint_count() == 4


def test_parse_petstore_has_path_parameter(petstore_3_0):
    parser = OpenAPIParser()
    spec = parser.parse(petstore_3_0)
    get_pet = next(
        e
        for e in spec.endpoints
        if e.path == "/pets/{petId}" and e.method == HTTPMethod.GET
    )
    path_params = get_pet.path_parameters()
    assert len(path_params) == 1
    assert path_params[0].name == "petId"
    assert path_params[0].required is True


def test_parse_petstore_security_scheme(petstore_3_0):
    parser = OpenAPIParser()
    spec = parser.parse(petstore_3_0)
    assert "bearerAuth" in spec.auth_schemes
    assert spec.auth_schemes["bearerAuth"].type == AuthType.BEARER


def test_parse_petstore_authenticated_endpoints(petstore_3_0):
    parser = OpenAPIParser()
    spec = parser.parse(petstore_3_0)
    auth_eps = spec.authenticated_endpoints()
    # /pets/{petId} GET and DELETE both have bearer
    assert len(auth_eps) == 2


def test_parse_3_1_yaml(petstore_3_1_yaml):
    parser = OpenAPIParser()
    spec = parser.parse(petstore_3_1_yaml)
    assert spec.source_format == SpecFormat.OPENAPI_3_1
    assert spec.endpoint_count() > 0


def test_parse_minimal_spec(minimal_spec):
    parser = OpenAPIParser()
    spec = parser.parse(minimal_spec)
    assert spec.name == "Minimal"
    assert spec.endpoint_count() == 1


def test_parse_malformed_strict_raises(malformed_spec):
    parser = OpenAPIParser(lenient=False)
    with pytest.raises(SpecParseError):
        parser.parse(malformed_spec)


def test_parse_malformed_lenient_warns(malformed_spec):
    parser = OpenAPIParser(lenient=True)
    spec = parser.parse(malformed_spec)
    assert len(spec.warnings) > 0
    assert any(w.code == "MALFORMED_STRUCTURE" for w in spec.warnings)


def test_parse_rejects_swagger_2_0():
    parser = OpenAPIParser()
    swagger = {
        "swagger": "2.0",
        "info": {"title": "X", "version": "1"},
        "paths": {},
    }
    with pytest.raises(UnsupportedSpecError):
        parser.parse(swagger)


def test_internal_ref_resolved(petstore_3_0):
    parser = OpenAPIParser()
    spec = parser.parse(petstore_3_0)
    # The 200 response on /pets GET references Pets schema → should be resolved
    list_pets = next(
        e
        for e in spec.endpoints
        if e.path == "/pets" and e.method == HTTPMethod.GET
    )
    resp_200 = list_pets.responses["200"]
    assert resp_200.schema_spec is not None
    assert resp_200.schema_spec.type == "array"


def test_external_ref_warning():
    parser = OpenAPIParser(lenient=True)
    spec_with_external = {
        "openapi": "3.0.0",
        "info": {"title": "X", "version": "1"},
        "paths": {
            "/x": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "https://example.com/schemas/X.json"
                                    }
                                }
                            },
                        }
                    }
                }
            }
        },
    }
    spec = parser.parse(spec_with_external)
    assert any(w.code == "EXTERNAL_REF_SKIPPED" for w in spec.warnings)
