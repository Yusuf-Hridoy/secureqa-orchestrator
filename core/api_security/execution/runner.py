"""Async HTTPX-based runner for executing SecurityTest objects."""

import asyncio
import json
import time

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from core.api_security.execution.models import (
    MAX_RESPONSE_BODY_BYTES,
    ExecutionResult,
    ExecutionStatus,
    ScanConfig,
)
from core.api_security.models import HTTPMethod
from core.api_security.test_models import SecurityTest, TestPayload
from core.logging_config import get_logger

logger = get_logger("httpx_runner")


# Methods we consider destructive (require explicit opt-in)
DESTRUCTIVE_METHODS = {
    HTTPMethod.POST,
    HTTPMethod.PUT,
    HTTPMethod.PATCH,
    HTTPMethod.DELETE,
}


class HTTPXRunner:
    """Concurrent async runner for SecurityTest execution."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run_batch(self, tests: list[SecurityTest]) -> list[ExecutionResult]:
        """Execute all tests concurrently, respecting the concurrency cap."""
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.request_timeout_seconds),
            follow_redirects=self.config.follow_redirects,
            headers={
                "User-Agent": self.config.user_agent,
                **self.config.extra_headers,
            },
        ) as client:
            tasks = [
                self._run_one_with_semaphore(client, test, semaphore)
                for test in tests
            ]
            return await asyncio.gather(*tasks)

    async def _run_one_with_semaphore(
        self,
        client: httpx.AsyncClient,
        test: SecurityTest,
        semaphore: asyncio.Semaphore,
    ) -> ExecutionResult:
        async with semaphore:
            return await self._run_one(client, test)

    async def _run_one(
        self, client: httpx.AsyncClient, test: SecurityTest
    ) -> ExecutionResult:
        # Destructive method gate
        if (
            test.payload.method in DESTRUCTIVE_METHODS
            and not self.config.allow_destructive_methods
        ):
            return ExecutionResult(
                test_id=test.test_id,
                status=ExecutionStatus.SKIPPED,
                skip_reason=(
                    f"Method {test.payload.method.value} is destructive and "
                    "allow_destructive_methods=False"
                ),
                final_method=test.payload.method,
            )

        url = self._build_url(test.payload)
        method = test.payload.method.value
        headers = dict(test.payload.headers)
        body_bytes, request_content_type = self._prepare_body(test.payload)
        if (
            request_content_type
            and "Content-Type" not in headers
            and body_bytes
        ):
            headers["Content-Type"] = request_content_type

        params = test.payload.query_params or None

        start = time.perf_counter()
        try:
            response = await self._send_with_retry(
                client, method, url, headers, params, body_bytes
            )
        except httpx.TimeoutException as e:
            latency_ms = (time.perf_counter() - start) * 1000
            return ExecutionResult(
                test_id=test.test_id,
                status=ExecutionStatus.TIMEOUT,
                error_message=str(e),
                latency_ms=latency_ms,
                final_url=url,
                final_method=test.payload.method,
            )
        except httpx.RequestError as e:
            latency_ms = (time.perf_counter() - start) * 1000
            logger.warning(
                f"Network error for test {test.test_id}: {e}"
            )
            return ExecutionResult(
                test_id=test.test_id,
                status=ExecutionStatus.NETWORK_ERROR,
                error_message=str(e),
                latency_ms=latency_ms,
                final_url=url,
                final_method=test.payload.method,
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            logger.error(
                f"Unexpected error for test {test.test_id}: {e}",
                exc_info=True,
            )
            return ExecutionResult(
                test_id=test.test_id,
                status=ExecutionStatus.NETWORK_ERROR,
                error_message=f"unexpected: {e}",
                latency_ms=latency_ms,
                final_url=url,
                final_method=test.payload.method,
            )

        latency_ms = (time.perf_counter() - start) * 1000

        # Capture response (truncate body)
        body_text = self._truncate_body(response)
        body_bytes_count = (
            len(response.content) if response.content is not None else 0
        )

        return ExecutionResult(
            test_id=test.test_id,
            status=ExecutionStatus.SUCCESS,
            http_status=response.status_code,
            response_headers={k: v for k, v in response.headers.items()},
            response_body=body_text,
            response_size_bytes=body_bytes_count,
            latency_ms=latency_ms,
            final_url=url,
            final_method=test.payload.method,
        )

    async def _send_with_retry(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict[str, str],
        params: dict[str, str] | None,
        body_bytes: bytes | None,
    ) -> httpx.Response:
        attempts = self.config.retry_attempts + 1  # initial attempt + retries

        @retry(
            stop=stop_after_attempt(attempts),
            wait=wait_exponential(
                multiplier=self.config.retry_backoff_seconds, min=0.1, max=10
            ),
            retry=retry_if_exception_type(
                (httpx.ConnectError, httpx.ReadError)
            ),
            reraise=True,
        )
        async def _do_request() -> httpx.Response:
            return await client.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                content=body_bytes,
            )

        return await _do_request()

    def _build_url(self, payload: TestPayload) -> str:
        """Resolve {param} placeholders in path and join with base URL."""
        resolved_path = payload.path
        for k, v in payload.path_params.items():
            resolved_path = resolved_path.replace(f"{{{k}}}", v)

        base = self.config.target_base_url.rstrip("/")
        path = (
            resolved_path
            if resolved_path.startswith("/")
            else "/" + resolved_path
        )
        # urljoin handles ports and schemes correctly
        return base + path

    def _prepare_body(
        self, payload: TestPayload
    ) -> tuple[bytes | None, str | None]:
        """Serialize body to bytes, return (bytes, content_type)."""
        if payload.body is None:
            return None, None
        if isinstance(payload.body, str):
            return (
                payload.body.encode("utf-8"),
                payload.content_type or "application/json",
            )
        if isinstance(payload.body, dict | list):
            return json.dumps(payload.body).encode("utf-8"), "application/json"
        return None, None

    def _truncate_body(self, response: httpx.Response) -> str:
        """Read response body up to MAX_RESPONSE_BODY_BYTES, decode safely."""
        content = response.content[:MAX_RESPONSE_BODY_BYTES]
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            return content.decode("utf-8", errors="replace")
