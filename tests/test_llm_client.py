"""Tests for the Gemini LLM client."""

import pytest
from google.api_core import exceptions as gae
from pydantic import BaseModel

from core.llm_client import GeminiClient, LLMOutputError


class SampleSchema(BaseModel):
    """Sample Pydantic model for structured output tests."""

    name: str
    score: int


def test_generate_text_success(mock_genai_model) -> None:
    """Happy path: generate_text returns the mocked response."""
    client = GeminiClient(api_key="test", model="test-model")
    result = client.generate_text("hello")
    assert result == "Mocked Gemini response"
    assert mock_genai_model.generate_content.call_count == 1


def test_generate_text_retries_on_resource_exhausted(
    mock_genai_model, mock_gemini_response
) -> None:
    """Tenacity should retry on ResourceExhausted and succeed on the 3rd attempt."""
    client = GeminiClient(api_key="test", model="test-model")
    mock_genai_model.generate_content.side_effect = [
        gae.ResourceExhausted("rate limit"),
        gae.ResourceExhausted("rate limit"),
        mock_gemini_response,
    ]
    result = client.generate_text("hello")
    assert result == "Mocked Gemini response"
    assert mock_genai_model.generate_content.call_count == 3


def test_generate_text_fails_after_max_retries(mock_genai_model) -> None:
    """After 3 failed attempts the original exception should be re-raised."""
    client = GeminiClient(api_key="test", model="test-model")
    mock_genai_model.generate_content.side_effect = gae.ResourceExhausted(
        "always fails"
    )
    with pytest.raises(gae.ResourceExhausted):
        client.generate_text("hello")
    assert mock_genai_model.generate_content.call_count == 3


def test_generate_structured_parses_valid_json(
    mock_genai_model, mock_gemini_response
) -> None:
    """Valid JSON from the model should deserialize into the Pydantic schema."""
    client = GeminiClient(api_key="test", model="test-model")
    mock_gemini_response.text = '{"name": "test", "score": 42}'
    result = client.generate_structured("prompt", SampleSchema)
    assert isinstance(result, SampleSchema)
    assert result.name == "test"
    assert result.score == 42


def test_generate_structured_raises_on_invalid_json(
    mock_genai_model, mock_gemini_response
) -> None:
    """Garbage responses should exhaust retries and raise LLMOutputError."""
    client = GeminiClient(api_key="test", model="test-model")
    mock_gemini_response.text = "garbage"
    with pytest.raises(LLMOutputError):
        client.generate_structured("prompt", SampleSchema)
    assert mock_genai_model.generate_content.call_count == 3


def test_generate_structured_strips_markdown_fences(
    mock_genai_model, mock_gemini_response
) -> None:
    """Markdown code fences should be stripped before JSON parsing."""
    client = GeminiClient(api_key="test", model="test-model")
    mock_gemini_response.text = '```json\n{"name": "test", "score": 99}\n```'
    result = client.generate_structured("prompt", SampleSchema)
    assert isinstance(result, SampleSchema)
    assert result.name == "test"
    assert result.score == 99
