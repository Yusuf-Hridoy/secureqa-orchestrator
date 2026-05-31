"""Tests for AuthContextResolver."""


from core.api_security.execution.auth_context import AuthContextResolver
from core.api_security.execution.models import AuthContext
from core.api_security.models import HTTPMethod
from core.api_security.test_models import (
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)


def _make_test(headers=None, path="/x", body=None):
    return SecurityTest(
        owasp_category=OWASPAPICategory.API1_BOLA,
        name="t",
        description="x",
        rationale="x",
        target_endpoint_path=path,
        target_endpoint_method=HTTPMethod.GET,
        payload=TestPayload(
            method=HTTPMethod.GET,
            path=path,
            headers=headers or {},
            body=body,
        ),
    )


def test_test_with_no_placeholders_resolves_unchanged():
    test = _make_test(headers={"X-Foo": "bar"})
    resolver = AuthContextResolver(AuthContext())
    result = resolver.resolve(test)
    assert result.was_resolved
    assert result.resolved_test.payload.headers == {"X-Foo": "bar"}


def test_missing_placeholder_skips_test():
    test = _make_test(headers={"Authorization": "Bearer {{regular_user_token}}"})
    resolver = AuthContextResolver(AuthContext())
    result = resolver.resolve(test)
    assert not result.was_resolved
    assert "regular_user_token" in result.skip_reason


def test_resolves_bearer_token():
    test = _make_test(headers={"Authorization": "Bearer {{regular_user_token}}"})
    resolver = AuthContextResolver(AuthContext(regular_user_token="my-token"))
    result = resolver.resolve(test)
    assert result.was_resolved
    assert result.resolved_test.payload.headers["Authorization"] == "Bearer my-token"


def test_resolves_path_param():
    test = _make_test(path="/users/{{user_b_resource_id}}")
    test.payload.path_params = {"id": "{{user_b_resource_id}}"}
    resolver = AuthContextResolver(AuthContext(user_b_resource_id="42"))
    result = resolver.resolve(test)
    assert result.was_resolved
    assert result.resolved_test.payload.path == "/users/42"
    assert result.resolved_test.payload.path_params == {"id": "42"}


def test_resolves_body_dict():
    test = _make_test(body={"user_id": "{{user_b_resource_id}}"})
    resolver = AuthContextResolver(AuthContext(user_b_resource_id="99"))
    result = resolver.resolve(test)
    assert result.was_resolved
    assert result.resolved_test.payload.body == {"user_id": "99"}


def test_resolves_from_extras():
    test = _make_test(headers={"X-Custom": "{{my_custom_value}}"})
    resolver = AuthContextResolver(AuthContext(extras={"my_custom_value": "hello"}))
    result = resolver.resolve(test)
    assert result.was_resolved
    assert result.resolved_test.payload.headers["X-Custom"] == "hello"


def test_multiple_placeholders_all_present():
    test = _make_test(
        headers={
            "Authorization": "Bearer {{user_a_token}}",
            "X-Test": "{{user_b_resource_id}}",
        }
    )
    resolver = AuthContextResolver(
        AuthContext(user_a_token="aaa", user_b_resource_id="bbb")
    )
    result = resolver.resolve(test)
    assert result.was_resolved
    assert result.resolved_test.payload.headers["Authorization"] == "Bearer aaa"
    assert result.resolved_test.payload.headers["X-Test"] == "bbb"


def test_one_missing_blocks_resolution():
    test = _make_test(
        headers={
            "Authorization": "Bearer {{user_a_token}}",
            "X-Other": "{{user_b_token}}",
        }
    )
    resolver = AuthContextResolver(AuthContext(user_a_token="aaa"))  # no b
    result = resolver.resolve(test)
    assert not result.was_resolved
    assert "user_b_token" in result.skip_reason


def test_original_test_not_mutated():
    test = _make_test(headers={"Authorization": "Bearer {{user_a_token}}"})
    original_headers = dict(test.payload.headers)
    resolver = AuthContextResolver(AuthContext(user_a_token="xyz"))
    resolver.resolve(test)
    assert test.payload.headers == original_headers
