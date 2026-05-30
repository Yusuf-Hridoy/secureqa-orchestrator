"""Tests for the API3 Property Authorization (Mass Assignment) generator."""


from core.api_security.generators.api3_property_auth import (
    SENSITIVE_FIELDS,
    PropertyAuthGenerator,
)
from core.api_security.models import HTTPMethod
from core.api_security.test_models import OWASPAPICategory


def test_no_body_endpoints_no_tests(empty_api_spec):
    gen = PropertyAuthGenerator()
    assert gen.generate(empty_api_spec) == []


def test_generates_for_post_with_body(simple_api_spec):
    gen = PropertyAuthGenerator()
    tests = gen.generate(simple_api_spec)
    # POST /users has a body → one test per sensitive field
    assert len(tests) == len(SENSITIVE_FIELDS)


def test_all_category_api3(simple_api_spec):
    gen = PropertyAuthGenerator()
    for t in gen.generate(simple_api_spec):
        assert t.owasp_category == OWASPAPICategory.API3_PROPERTY_AUTH


def test_each_test_injects_one_sensitive_field(simple_api_spec):
    gen = PropertyAuthGenerator()
    tests = gen.generate(simple_api_spec)
    for t in tests:
        # Find which sensitive field this test targets
        body = t.payload.body
        present = [f for f in SENSITIVE_FIELDS if f in body]
        assert len(present) >= 1


def test_get_endpoint_skipped(simple_api_spec):
    """GET /users/{userId} should not produce mass-assignment tests."""
    gen = PropertyAuthGenerator()
    for t in gen.generate(simple_api_spec):
        assert t.target_endpoint_method != HTTPMethod.GET


def test_is_admin_field_included(simple_api_spec):
    gen = PropertyAuthGenerator()
    tests = gen.generate(simple_api_spec)
    assert any("is_admin" in t.name for t in tests)
