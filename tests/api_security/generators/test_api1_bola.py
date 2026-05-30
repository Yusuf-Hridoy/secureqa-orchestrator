"""Tests for the API1 BOLA generator."""

from unittest.mock import MagicMock

from core.api_security.generators.api1_bola import SUBSTITUTION_IDS, BOLAGenerator
from core.api_security.generators.llm_helper import LLMPayloadSuggestion
from core.api_security.test_models import OWASPAPICategory


def test_no_path_params_no_tests(empty_api_spec):
    gen = BOLAGenerator()
    assert gen.generate(empty_api_spec) == []


def test_generates_substitution_tests(simple_api_spec):
    gen = BOLAGenerator()
    tests = gen.generate(simple_api_spec)
    # /users/{userId} has 1 path param → 5 substitution tests + 1 cross-tenant = 6
    assert len(tests) == len(SUBSTITUTION_IDS) + 1


def test_all_tests_are_bola_category(simple_api_spec):
    gen = BOLAGenerator()
    for t in gen.generate(simple_api_spec):
        assert t.owasp_category == OWASPAPICategory.API1_BOLA


def test_substituted_path_uses_id(simple_api_spec):
    gen = BOLAGenerator()
    tests = gen.generate(simple_api_spec)
    # Find the test substituting userId=0
    sub0 = next(t for t in tests if "userId=0" in t.name)
    assert sub0.payload.path == "/users/0"


def test_cross_tenant_test_marked_requires_two_users(simple_api_spec):
    gen = BOLAGenerator()
    tests = gen.generate(simple_api_spec)
    cross = next(t for t in tests if "cross-tenant" in t.name)
    assert cross.requires_two_users is True


def test_auth_required_propagated(simple_api_spec):
    """The /users/{userId} endpoint has bearerAuth → tests inherit requires_auth_context."""
    gen = BOLAGenerator()
    tests = gen.generate(simple_api_spec)
    assert all(t.requires_auth_context for t in tests)


def test_indicator_severity_is_high_or_critical(simple_api_spec):
    gen = BOLAGenerator()
    for t in gen.generate(simple_api_spec):
        assert t.severity_hint.value in ("high", "critical")


def test_llm_path_invoked_when_enabled(simple_api_spec):
    helper = MagicMock()
    helper.suggest_payloads.return_value = [
        LLMPayloadSuggestion(
            payload_description="llm-bola-1",
            request_body={},
            query_params={},
            rationale="creative test",
        )
    ]
    gen = BOLAGenerator(use_llm=True, llm_helper=helper)
    tests = gen.generate(simple_api_spec)
    assert helper.suggest_payloads.called
    assert any("llm" in t.name for t in tests)
