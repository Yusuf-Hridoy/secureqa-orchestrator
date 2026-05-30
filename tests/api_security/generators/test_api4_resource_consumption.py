"""Tests for the API4 Resource Consumption generator."""


from core.api_security.generators.api4_resource_consumption import (
    ResourceConsumptionGenerator,
)
from core.api_security.models import (
    APISpec,
    Endpoint,
    HTTPMethod,
    Parameter,
    ParameterLocation,
    SpecFormat,
)
from core.api_security.test_models import OWASPAPICategory


def test_empty_spec(empty_api_spec):
    gen = ResourceConsumptionGenerator()
    assert gen.generate(empty_api_spec) == []


def test_pagination_param_triggers_tests():
    spec = APISpec(
        name="X",
        source_format=SpecFormat.OPENAPI_3_0,
        endpoints=[
            Endpoint(
                path="/items",
                method=HTTPMethod.GET,
                parameters=[Parameter(name="limit", location=ParameterLocation.QUERY)],
            ),
        ],
    )
    tests = ResourceConsumptionGenerator().generate(spec)
    # 1 oversized + 1 negative = 2
    assert len(tests) == 2


def test_deep_nesting_for_body_endpoint(simple_api_spec):
    """POST /users in simple_api_spec has a body → 1 deep-nesting test."""
    gen = ResourceConsumptionGenerator()
    tests = gen.generate(simple_api_spec)
    deep = [t for t in tests if "deep-nesting" in t.name]
    assert len(deep) == 1


def test_category_is_api4(simple_api_spec):
    gen = ResourceConsumptionGenerator()
    for t in gen.generate(simple_api_spec):
        assert t.owasp_category == OWASPAPICategory.API4_RESOURCE_CONSUMPTION
