"""Tests for the Generator base class and SecurityTest model."""

import pytest
from pydantic import ValidationError

from core.api_security.generators.base import Generator
from core.api_security.models import APISpec, HTTPMethod, SpecFormat
from core.api_security.test_models import (
    ExpectedIndicator,
    IndicatorType,
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)


def test_security_test_basic_creation():
    test = SecurityTest(
        owasp_category=OWASPAPICategory.API1_BOLA,
        name="test-1",
        description="Basic test",
        rationale="Endpoint takes a path ID",
        target_endpoint_path="/users/{id}",
        target_endpoint_method=HTTPMethod.GET,
        payload=TestPayload(method=HTTPMethod.GET, path="/users/1"),
    )
    assert test.owasp_category == OWASPAPICategory.API1_BOLA
    assert test.test_id  # auto-generated


def test_expected_indicator_with_weight():
    ind = ExpectedIndicator(
        type=IndicatorType.STATUS_CODE_IS,
        value=200,
        description="200 OK on cross-user access indicates BOLA",
        weight=0.9,
    )
    assert ind.weight == 0.9


def test_indicator_weight_validation():
    with pytest.raises(ValidationError):
        ExpectedIndicator(type=IndicatorType.STATUS_CODE_IS, value=200, weight=1.5)


def test_generator_requires_llm_helper_when_use_llm_true():
    class DummyGen(Generator):
        category = OWASPAPICategory.API1_BOLA
        name = "dummy"

        def generate(self, spec: APISpec):
            return []

    with pytest.raises(ValueError, match="llm_helper is required"):
        DummyGen(use_llm=True)


def test_generator_empty_spec_returns_empty_list():
    class DummyGen(Generator):
        category = OWASPAPICategory.API1_BOLA
        name = "dummy"

        def generate(self, spec: APISpec):
            return []

    gen = DummyGen()
    empty = APISpec(name="Empty", source_format=SpecFormat.OPENAPI_3_0)
    assert gen.generate(empty) == []
