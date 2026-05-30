"""Tests for the API5 Function-Level Auth generator."""


from core.api_security.generators.api5_function_auth import FunctionLevelAuthGenerator
from core.api_security.test_models import OWASPAPICategory


def test_empty_spec(empty_api_spec):
    gen = FunctionLevelAuthGenerator()
    assert gen.generate(empty_api_spec) == []


def test_detects_admin_path(admin_endpoint_spec):
    gen = FunctionLevelAuthGenerator()
    tests = gen.generate(admin_endpoint_spec)
    # /admin/users (admin path) → 2 tests; /users/{id}/delete (DELETE) → 3 tests
    # /users/me → not admin → 0 tests
    admin_path_tests = [t for t in tests if "/admin" in t.target_endpoint_path]
    assert len(admin_path_tests) == 2


def test_delete_user_endpoint_flagged(admin_endpoint_spec):
    gen = FunctionLevelAuthGenerator()
    tests = gen.generate(admin_endpoint_spec)
    delete_tests = [t for t in tests if "/users/{id}/delete" in t.target_endpoint_path]
    assert len(delete_tests) >= 2  # unauthenticated + regular_user + privileged_delete


def test_users_me_not_admin(admin_endpoint_spec):
    gen = FunctionLevelAuthGenerator()
    tests = gen.generate(admin_endpoint_spec)
    me_tests = [t for t in tests if "/users/me" in t.target_endpoint_path]
    assert me_tests == []


def test_category_is_api5(admin_endpoint_spec):
    gen = FunctionLevelAuthGenerator()
    for t in gen.generate(admin_endpoint_spec):
        assert t.owasp_category == OWASPAPICategory.API5_FUNCTION_AUTH
