"""Tests for the LLM payload helper. All Gemini calls are mocked."""

from unittest.mock import MagicMock

import pytest

from core.api_security.generators.llm_helper import (
    LLMPayloadHelper,
    LLMPayloadResponse,
    LLMPayloadSuggestion,
)
from core.api_security.models import Endpoint, HTTPMethod
from core.api_security.test_models import OWASPAPICategory
from core.llm_client import LLMOutputError


@pytest.fixture
def fake_endpoint():
    return Endpoint(path="/users/{id}", method=HTTPMethod.GET)


@pytest.fixture
def mock_client():
    c = MagicMock()
    c.generate_structured.return_value = LLMPayloadResponse(
        suggestions=[
            LLMPayloadSuggestion(
                payload_description="BOLA cross-tenant",
                request_body={},
                query_params={},
                rationale="Tests cross-user access via ID substitution",
            )
        ]
    )
    return c


def test_returns_suggestions_on_success(mock_client, fake_endpoint):
    helper = LLMPayloadHelper(client=mock_client)
    out = helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API1_BOLA)
    assert len(out) == 1
    assert out[0].payload_description == "BOLA cross-tenant"


def test_caches_per_endpoint_and_category(mock_client, fake_endpoint):
    helper = LLMPayloadHelper(client=mock_client)
    helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API1_BOLA)
    helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API1_BOLA)
    # Second call should hit cache → client called only once
    assert mock_client.generate_structured.call_count == 1


def test_different_categories_not_cached_together(mock_client, fake_endpoint):
    helper = LLMPayloadHelper(client=mock_client)
    helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API1_BOLA)
    helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API7_SSRF)
    assert mock_client.generate_structured.call_count == 2


def test_returns_empty_on_llm_error(fake_endpoint):
    client = MagicMock()
    client.generate_structured.side_effect = LLMOutputError("validation failed")
    helper = LLMPayloadHelper(client=client)
    out = helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API1_BOLA)
    assert out == []


def test_returns_empty_on_unexpected_error(fake_endpoint):
    client = MagicMock()
    client.generate_structured.side_effect = RuntimeError("boom")
    helper = LLMPayloadHelper(client=client)
    out = helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API1_BOLA)
    assert out == []


def test_max_suggestions_respected(fake_endpoint):
    client = MagicMock()
    client.generate_structured.return_value = LLMPayloadResponse(
        suggestions=[
            LLMPayloadSuggestion(
                payload_description=f"p{i}",
                request_body={},
                query_params={},
                rationale="x",
            )
            for i in range(10)
        ]
    )
    helper = LLMPayloadHelper(client=client, max_suggestions=3)
    out = helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API1_BOLA)
    assert len(out) == 3


def test_clear_cache(mock_client, fake_endpoint):
    helper = LLMPayloadHelper(client=mock_client)
    helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API1_BOLA)
    helper.clear_cache()
    helper.suggest_payloads(fake_endpoint, OWASPAPICategory.API1_BOLA)
    # Cache cleared → second call hits client again
    assert mock_client.generate_structured.call_count == 2
