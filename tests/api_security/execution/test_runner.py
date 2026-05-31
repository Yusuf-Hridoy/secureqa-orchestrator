"""Tests for HTTPXRunner. All HTTP mocked via httpx.MockTransport."""

import httpx
import pytest

from core.api_security.execution.models import ExecutionStatus
from core.api_security.execution.runner import HTTPXRunner
from tests.api_security.execution.conftest import make_test


@pytest.mark.asyncio
async def test_runner_success(monkeypatch, scan_config, get_test):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"X-Demo": "1"}, content=b'{"ok":true}')

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        "core.api_security.execution.runner.httpx.AsyncClient", _PatchedClient
    )

    runner = HTTPXRunner(scan_config)
    results = await runner.run_batch([get_test])
    assert len(results) == 1
    r = results[0]
    assert r.status == ExecutionStatus.SUCCESS
    assert r.http_status == 200
    assert r.response_body == '{"ok":true}'
    assert r.response_headers.get("x-demo") == "1"
    assert r.latency_ms > 0


@pytest.mark.asyncio
async def test_runner_skips_destructive(scan_config, post_test):
    runner = HTTPXRunner(scan_config)  # allow_destructive_methods=False
    results = await runner.run_batch([post_test])
    assert len(results) == 1
    assert results[0].status == ExecutionStatus.SKIPPED
    assert "destructive" in results[0].skip_reason.lower()


@pytest.mark.asyncio
async def test_runner_runs_destructive_when_allowed(
    monkeypatch, scan_config_with_destructive_allowed, post_test
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201)

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        "core.api_security.execution.runner.httpx.AsyncClient", _PatchedClient
    )

    runner = HTTPXRunner(scan_config_with_destructive_allowed)
    results = await runner.run_batch([post_test])
    assert results[0].status == ExecutionStatus.SUCCESS
    assert results[0].http_status == 201


@pytest.mark.asyncio
async def test_runner_handles_network_error(monkeypatch, scan_config, get_test):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated dns failure")

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        "core.api_security.execution.runner.httpx.AsyncClient", _PatchedClient
    )

    runner = HTTPXRunner(scan_config)
    results = await runner.run_batch([get_test])
    assert results[0].status == ExecutionStatus.NETWORK_ERROR
    assert "dns failure" in results[0].error_message


@pytest.mark.asyncio
async def test_runner_handles_timeout(monkeypatch, scan_config, get_test):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("simulated timeout")

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        "core.api_security.execution.runner.httpx.AsyncClient", _PatchedClient
    )

    runner = HTTPXRunner(scan_config)
    results = await runner.run_batch([get_test])
    assert results[0].status == ExecutionStatus.TIMEOUT


@pytest.mark.asyncio
async def test_runner_concurrency_doesnt_break(monkeypatch, scan_config):
    """Run 10 tests with concurrency=3 — all should complete."""
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, content=b"{}")

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        "core.api_security.execution.runner.httpx.AsyncClient", _PatchedClient
    )

    tests = [make_test(path=f"/x/{i}") for i in range(10)]
    runner = HTTPXRunner(scan_config)
    results = await runner.run_batch(tests)
    assert len(results) == 10
    assert all(r.status == ExecutionStatus.SUCCESS for r in results)
    assert call_count["n"] == 10


@pytest.mark.asyncio
async def test_url_built_with_path_params(monkeypatch, scan_config):
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200, content=b"{}")

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        "core.api_security.execution.runner.httpx.AsyncClient", _PatchedClient
    )

    test = make_test(path="/users/{userId}")
    test.payload.path_params = {"userId": "42"}

    runner = HTTPXRunner(scan_config)
    await runner.run_batch([test])
    assert any("/users/42" in u for u in requested_urls)


@pytest.mark.asyncio
async def test_response_body_truncated(monkeypatch, scan_config, get_test):
    huge = b"A" * (300 * 1024)  # 300KB

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=huge)

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        "core.api_security.execution.runner.httpx.AsyncClient", _PatchedClient
    )

    runner = HTTPXRunner(scan_config)
    results = await runner.run_batch([get_test])
    # Truncated to MAX_RESPONSE_BODY_BYTES (256KB)
    assert len(results[0].response_body) <= 256 * 1024
    # But original size is still recorded
    assert results[0].response_size_bytes == 300 * 1024
