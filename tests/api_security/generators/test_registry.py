"""Tests for GeneratorRegistry."""


from core.api_security.generators.registry import (
    DEFAULT_GENERATOR_CLASSES,
    GeneratorRegistry,
)
from core.api_security.test_models import OWASPAPICategory


def test_default_registry_has_all_8_generators():
    reg = GeneratorRegistry()
    assert len(reg.generators) == 8
    assert len(DEFAULT_GENERATOR_CLASSES) == 8


def test_generate_all_empty_spec(empty_api_spec):
    reg = GeneratorRegistry()
    tests = reg.generate_all(empty_api_spec)
    # API9 still probes hidden paths even on empty spec
    assert len(tests) > 0
    # All tests should be in our 8 categories
    for t in tests:
        assert t.owasp_category in {
            OWASPAPICategory.API1_BOLA,
            OWASPAPICategory.API2_BROKEN_AUTH,
            OWASPAPICategory.API3_PROPERTY_AUTH,
            OWASPAPICategory.API4_RESOURCE_CONSUMPTION,
            OWASPAPICategory.API5_FUNCTION_AUTH,
            OWASPAPICategory.API7_SSRF,
            OWASPAPICategory.API8_MISCONFIGURATION,
            OWASPAPICategory.API9_INVENTORY,
        }


def test_generate_all_simple_spec(simple_api_spec):
    reg = GeneratorRegistry()
    tests = reg.generate_all(simple_api_spec)
    assert len(tests) > 0


def test_tests_by_category(simple_api_spec):
    reg = GeneratorRegistry()
    result = reg.tests_by_category(simple_api_spec)
    assert len(result) == 8
    # BOLA should have tests (path-param endpoint present)
    assert len(result[OWASPAPICategory.API1_BOLA]) > 0


def test_enabled_categories_filter(simple_api_spec):
    reg = GeneratorRegistry(enabled_categories={OWASPAPICategory.API1_BOLA})
    assert len(reg.generators) == 1
    tests = reg.generate_all(simple_api_spec)
    assert all(t.owasp_category == OWASPAPICategory.API1_BOLA for t in tests)


def test_generator_exception_does_not_break_scan(monkeypatch, simple_api_spec):
    """If one generator raises, the registry continues with others."""
    reg = GeneratorRegistry()

    # Break the first generator
    def boom(self, spec):
        raise RuntimeError("simulated crash")
    monkeypatch.setattr(reg.generators[0].__class__, "generate", boom)

    tests = reg.generate_all(simple_api_spec)
    # Other generators still ran
    assert len(tests) > 0
