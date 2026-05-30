"""Tests for the API2 Broken Authentication generator."""


from core.api_security.generators.api2_broken_auth import (
    ALG_NONE_JWT,
    EXPIRED_JWT,
    BrokenAuthGenerator,
)
from core.api_security.test_models import OWASPAPICategory


def test_no_auth_endpoint_no_tests(empty_api_spec):
    gen = BrokenAuthGenerator()
    assert gen.generate(empty_api_spec) == []


def test_generates_for_authenticated_endpoint(simple_api_spec):
    gen = BrokenAuthGenerator()
    tests = gen.generate(simple_api_spec)
    # /users/{userId} has bearerAuth → 6 tests (no auth, empty bearer, malformed, expired, alg-none, wrong scheme)
    assert len(tests) == 6


def test_all_in_api2_category(simple_api_spec):
    gen = BrokenAuthGenerator()
    for t in gen.generate(simple_api_spec):
        assert t.owasp_category == OWASPAPICategory.API2_BROKEN_AUTH


def test_no_auth_test_has_no_authorization_header(simple_api_spec):
    gen = BrokenAuthGenerator()
    no_auth = next(
        t for t in gen.generate(simple_api_spec) if "no-token" in t.name
    )
    assert "Authorization" not in no_auth.payload.headers


def test_expired_jwt_included(simple_api_spec):
    gen = BrokenAuthGenerator()
    expired = next(
        t for t in gen.generate(simple_api_spec) if "expired-jwt" in t.name
    )
    assert EXPIRED_JWT in expired.payload.headers["Authorization"]


def test_alg_none_test_present(simple_api_spec):
    gen = BrokenAuthGenerator()
    alg_none = next(
        t for t in gen.generate(simple_api_spec) if "alg-none" in t.name
    )
    assert ALG_NONE_JWT in alg_none.payload.headers["Authorization"]
    assert alg_none.severity_hint.value == "critical"


def test_unauthenticated_endpoint_skipped(simple_api_spec):
    """POST /users has no security — should not generate auth tests."""
    gen = BrokenAuthGenerator()
    tests = gen.generate(simple_api_spec)
    for t in tests:
        assert t.target_endpoint_path == "/users/{userId}"
