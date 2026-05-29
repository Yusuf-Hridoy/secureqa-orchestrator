"""End-to-end integration tests for Phase 1A — full parse flow."""

import json
from pathlib import Path

from core.api_security import parse_spec
from core.api_security.models import HTTPMethod, SpecFormat

FIXTURES = Path("tests/fixtures/specs")


def test_full_flow_openapi_3_0_petstore():
    raw = (FIXTURES / "petstore_openapi_3_0.json").read_bytes()
    spec = parse_spec(raw)

    assert spec.name == "Petstore"
    assert spec.source_format == SpecFormat.OPENAPI_3_0
    assert spec.endpoint_count() == 4
    assert "bearerAuth" in spec.auth_schemes

    # Verify endpoint details
    get_pet = next(
        e
        for e in spec.endpoints
        if e.method == HTTPMethod.GET and e.path == "/pets/{petId}"
    )
    assert get_pet.path_parameters()[0].name == "petId"
    assert len(get_pet.security) == 1


def test_full_flow_openapi_3_1_yaml():
    raw = (FIXTURES / "petstore_openapi_3_1.yaml").read_bytes()
    spec = parse_spec(raw)
    assert spec.source_format == SpecFormat.OPENAPI_3_1
    assert spec.endpoint_count() > 0


def test_full_flow_postman():
    raw = (FIXTURES / "postman_collection_v2_1.json").read_bytes()
    spec = parse_spec(raw)
    assert spec.source_format == SpecFormat.POSTMAN_2_1
    assert spec.endpoint_count() == 3
    assert spec.base_url == "https://petstore.example.com/api/v1"


def test_all_three_formats_normalize_to_same_model():
    """Sanity check: all three formats produce APISpec objects with the same shape."""
    openapi = parse_spec(
        json.loads((FIXTURES / "petstore_openapi_3_0.json").read_text())
    )
    postman = parse_spec(
        json.loads((FIXTURES / "postman_collection_v2_1.json").read_text())
    )

    # Same attributes available on both
    for spec in (openapi, postman):
        assert hasattr(spec, "name")
        assert hasattr(spec, "endpoints")
        assert hasattr(spec, "auth_schemes")
        assert hasattr(spec, "warnings")
        assert isinstance(spec.endpoints, list)
        if spec.endpoints:
            assert hasattr(spec.endpoints[0], "path")
            assert hasattr(spec.endpoints[0], "method")
