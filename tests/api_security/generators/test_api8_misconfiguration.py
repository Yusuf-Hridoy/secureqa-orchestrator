"""Tests for API8 Misconfiguration."""


from core.api_security.generators.api8_misconfiguration import (
    REQUIRED_SECURITY_HEADERS,
    MisconfigurationGenerator,
)
from core.api_security.test_models import OWASPAPICategory


def test_empty_spec(empty_api_spec):
    gen = MisconfigurationGenerator()
    assert gen.generate(empty_api_spec) == []


def test_one_test_per_security_header(simple_api_spec):
    gen = MisconfigurationGenerator()
    tests = gen.generate(simple_api_spec)
    header_tests = [t for t in tests if t.name.startswith("MISC-header-missing")]
    assert len(header_tests) == len(REQUIRED_SECURITY_HEADERS)


def test_verbose_error_test_present(simple_api_spec):
    gen = MisconfigurationGenerator()
    tests = gen.generate(simple_api_spec)
    assert any("verbose-error" in t.name for t in tests)


def test_header_indicator_targets_header_name(simple_api_spec):
    gen = MisconfigurationGenerator()
    tests = gen.generate(simple_api_spec)
    hsts = next(t for t in tests if "Strict-Transport-Security" in t.name)
    assert any(i.target == "Strict-Transport-Security" for i in hsts.indicators)


def test_category_is_api8(simple_api_spec):
    gen = MisconfigurationGenerator()
    for t in gen.generate(simple_api_spec):
        assert t.owasp_category == OWASPAPICategory.API8_MISCONFIGURATION
