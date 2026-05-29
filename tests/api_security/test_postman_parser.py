"""Tests for the Postman Collection v2.1 parser."""

import json
from pathlib import Path

import pytest

from core.api_security.exceptions import UnsupportedSpecError
from core.api_security.models import (
    HTTPMethod,
    SpecFormat,
)
from core.api_security.parsers.postman_parser import PostmanParser

FIXTURES = Path("tests/fixtures/specs")


@pytest.fixture
def postman_collection():
    return json.loads((FIXTURES / "postman_collection_v2_1.json").read_text())


@pytest.fixture
def postman_minimal():
    return json.loads((FIXTURES / "postman_minimal.json").read_text())


def test_can_parse_postman_v2_1(postman_collection):
    parser = PostmanParser()
    assert parser.can_parse(postman_collection)


def test_cannot_parse_openapi():
    parser = PostmanParser()
    openapi = {"openapi": "3.0.0", "info": {"title": "X", "version": "1"}}
    assert parser.can_parse(openapi) is False


def test_parse_basic_metadata(postman_collection):
    spec = PostmanParser().parse(postman_collection)
    assert spec.name == "Petstore Postman Collection"
    assert spec.source_format == SpecFormat.POSTMAN_2_1


def test_parse_endpoint_count(postman_collection):
    spec = PostmanParser().parse(postman_collection)
    # 3 requests in collection
    assert spec.endpoint_count() == 3


def test_parse_methods(postman_collection):
    spec = PostmanParser().parse(postman_collection)
    methods = {e.method for e in spec.endpoints}
    assert HTTPMethod.GET in methods
    assert HTTPMethod.POST in methods


def test_parse_resolves_variables(postman_collection):
    """baseUrl variable should resolve in base_url."""
    spec = PostmanParser().parse(postman_collection)
    assert spec.base_url == "https://petstore.example.com/api/v1"


def test_parse_path_params_colon_syntax(postman_collection):
    """`:petId` in URL should become `{petId}` and be a path parameter."""
    spec = PostmanParser().parse(postman_collection)
    get_pet = next(
        e
        for e in spec.endpoints
        if e.method == HTTPMethod.GET and "petId" in e.path
    )
    assert "{petId}" in get_pet.path
    path_params = get_pet.path_parameters()
    assert any(p.name == "petId" for p in path_params)


def test_parse_query_params(postman_collection):
    spec = PostmanParser().parse(postman_collection)
    list_pets = next(
        e
        for e in spec.endpoints
        if e.method == HTTPMethod.GET and e.path == "/pets"
    )
    query_params = list_pets.query_parameters()
    assert any(p.name == "limit" for p in query_params)


def test_parse_request_body_for_post(postman_collection):
    spec = PostmanParser().parse(postman_collection)
    create_pet = next(e for e in spec.endpoints if e.method == HTTPMethod.POST)
    assert create_pet.request_body is not None
    assert create_pet.request_body.content_type == "application/json"


def test_parse_minimal_collection(postman_minimal):
    spec = PostmanParser().parse(postman_minimal)
    assert spec.endpoint_count() == 1
    assert spec.endpoints[0].method == HTTPMethod.GET


def test_unresolved_variable_warning():
    """Variables with no value in collection should produce a warning."""
    parser = PostmanParser()
    collection = {
        "info": {
            "name": "Test",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": [
            {
                "name": "X",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "{{unknownVar}}/path",
                        "host": ["{{unknownVar}}"],
                        "path": ["path"],
                    },
                },
            }
        ],
    }
    spec = parser.parse(collection)
    assert any(w.code == "UNRESOLVED_VARIABLE" for w in spec.warnings)


def test_rejects_non_postman_schema():
    parser = PostmanParser()
    bogus = {"info": {"name": "X", "schema": "https://example.com/random"}}
    with pytest.raises(UnsupportedSpecError):
        parser.parse(bogus)
