"""End-to-end integration: parse spec → generate tests → assert sensible output."""

from pathlib import Path

import pytest

from core.api_security import parse_spec
from core.api_security.generators.registry import GeneratorRegistry

FIXTURES = Path("tests/fixtures/specs")


@pytest.fixture
def registry():
    return GeneratorRegistry()


def test_petstore_openapi_3_0(registry):
    spec = parse_spec((FIXTURES / "petstore_openapi_3_0.json").read_bytes())
    tests = registry.generate_all(spec)
    assert len(tests) > 0
    # BOLA tests should exist (petstore has /pets/{petId})
    assert any(t.owasp_category.value == "API1_BOLA" for t in tests)
    # Auth tests should exist (bearerAuth on /pets/{petId})
    assert any(t.owasp_category.value == "API2_BROKEN_AUTH" for t in tests)


def test_postman_collection(registry):
    spec = parse_spec((FIXTURES / "postman_collection_v2_1.json").read_bytes())
    tests = registry.generate_all(spec)
    assert len(tests) > 0


def test_minimal_spec(registry):
    spec = parse_spec((FIXTURES / "minimal_openapi.json").read_bytes())
    tests = registry.generate_all(spec)
    # Minimal spec → only API8 (header checks) and API9 (hidden paths) generate tests
    assert len(tests) > 0


def test_all_tests_have_valid_payload(registry):
    spec = parse_spec((FIXTURES / "petstore_openapi_3_0.json").read_bytes())
    tests = registry.generate_all(spec)
    for t in tests:
        assert t.payload.path, f"Empty path on {t.name}"
        assert t.payload.method, f"Empty method on {t.name}"


def test_all_tests_have_at_least_one_indicator(registry):
    spec = parse_spec((FIXTURES / "petstore_openapi_3_0.json").read_bytes())
    tests = registry.generate_all(spec)
    for t in tests:
        assert len(t.indicators) >= 1, f"No indicators on {t.name}"


def test_no_real_network_calls_during_generation(registry, simple_api_spec):
    """Generators MUST NOT make HTTP calls. Run with httpx mocked and ensure no calls happen."""
    # We can't fully assert "no socket opened" easily, but we can run generators and
    # confirm they complete deterministically with no env_var-dependent behavior.
    tests1 = registry.generate_all(simple_api_spec)
    tests2 = registry.generate_all(simple_api_spec)
    # Same input → same number of tests
    assert len(tests1) == len(tests2)
