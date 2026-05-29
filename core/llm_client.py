"""Gemini LLM client with retry logic and structured output support."""

import hashlib
import json
import time

import google.generativeai as genai
from google.api_core import exceptions as gae
from pydantic import BaseModel, ValidationError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from config.settings import settings
from core.logging_config import get_logger


class LLMOutputError(Exception):
    """Raised when structured output fails validation after all retries."""


class GeminiClient:
    """Thin wrapper around Google's Generative AI API with resilience and logging."""

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self._api_key = api_key or settings.gemini_api_key.get_secret_value()
        self._model_name = model or settings.gemini_model
        genai.configure(api_key=self._api_key)
        self._logger = get_logger(__name__)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(min=1, max=4),
        retry=retry_if_exception_type(
            (gae.ResourceExhausted, gae.ServiceUnavailable, gae.DeadlineExceeded)
        ),
        reraise=True,
    )
    def generate_text(
        self,
        prompt: str,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Generate plain text from the configured Gemini model."""
        model = genai.GenerativeModel(self._model_name)

        generation_config: dict[str, float | int] = {}
        if temperature is not None:
            generation_config["temperature"] = temperature
        if max_tokens is not None:
            generation_config["max_output_tokens"] = max_tokens

        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:8]
        start = time.perf_counter()

        response = model.generate_content(
            prompt,
            generation_config=generation_config or None,
            request_options={"timeout": settings.llm_timeout_seconds},
        )

        elapsed_ms = int((time.perf_counter() - start) * 1000)
        try:
            text = response.text or ""
        except ValueError:
            text = ""

        self._logger.info(
            "LLM call completed",
            prompt_hash=prompt_hash,
            latency_ms=elapsed_ms,
            model=self._model_name,
            prompt_length=len(prompt),
            response_length=len(text),
        )

        return text

    def _strip_markdown(self, text: str) -> str:
        """Remove markdown code fences from a model response."""
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    def generate_structured(
        self,
        prompt: str,
        response_model: type[BaseModel],
        *,
        temperature: float | None = None,
    ) -> BaseModel:
        """Generate structured output validated against a Pydantic model."""
        schema = json.dumps(response_model.model_json_schema(), indent=2)
        augmented = (
            f"{prompt}\n\nRespond ONLY with valid JSON matching this schema: "
            f"{schema}. No markdown, no code fences, no preamble."
        )

        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                raw = self.generate_text(augmented, temperature=temperature)
                cleaned = self._strip_markdown(raw)
                data = json.loads(cleaned)
                return response_model.model_validate(data)
            except (json.JSONDecodeError, ValidationError) as exc:
                last_error = exc
                self._logger.warning(
                    "Structured output validation failed, retrying",
                    attempt=attempt,
                    error=str(exc),
                )

        raise LLMOutputError(
            f"Failed to generate valid structured output after 3 attempts: {last_error}"
        )
