"""End-to-end integration test of the full Phase 1C pipeline."""

from pathlib import Path

import httpx
import pytest

from core.api_security import (
    ScanConfig,
    ScanOrchestrator,
    parse_spec,
)

FIXTURES = Path("tests/fixtures/specs")


@pytest.fixture
def mock_server_handler():
    """Mock server that returns realistic responses for security testing."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        # Simulate a missing-auth bug: /pets/{petId} returns 200 with no auth
        if path.startswith("/api/v1/pets/") and method == "GET":
            # No auth check (this is a "vulnerable" endpoint for testing)
            return httpx.Response(
                200,
                content=b'{"id":"1","name":"Rex"}',
                headers={"Content-Type": "application/json"},
            )

        # /pets list returns 200 — no security headers
        if path == "/api/v1/pets" and method == "GET":
            return httpx.Response(
                200,
                content=b'[{"id":"1","name":"Rex"}]',
                headers={"Content-Type": "application/json"},
                # NOTE: no HSTS, no CSP, no X-Frame-Options → API8 should fire
            )

        # Hidden paths return 404
        return httpx.Response(404, content=b'{"error":"not found"}')

    return handler


def test_full_pipeline_against_mock_petstore(
    mock_server_handler, monkeypatch, tmp_path
):
    """Parse Petstore, scan it against the mock server, assert findings."""

    # Patch httpx client used by runner
    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(mock_server_handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        "core.api_security.execution.runner.httpx.AsyncClient", _PatchedClient
    )

    # Patch storage so tests don't write to disk
    monkeypatch.setattr(
        "core.api_security.execution.orchestrator.save_scan",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "core.api_security.execution.orchestrator.log_audit",
        lambda *a, **kw: None,
    )

    # Load spec
    spec = parse_spec(
        (FIXTURES / "petstore_openapi_3_0.json").read_bytes()
    )

    # Configure scan against a staging URL (passes SafetyGuard)
    config = ScanConfig(
        target_base_url="https://api.staging.petstore.example.com/api/v1",
        concurrency=3,
        request_timeout_seconds=2.0,
        retry_attempts=0,
        use_llm_classification=False,  # rule-based only for deterministic test
        use_llm_explanations=False,
        allow_destructive_methods=False,
    )
    orchestrator = ScanOrchestrator(config=config)

    # Drain progress events
    events = list(orchestrator.run_scan(spec))
    final = events[-1]

    assert final.step == "complete"
    assert final.percent == 100

    findings = final.partial_findings

    # Expectations:
    # - API8 missing-header tests should produce findings (mock server has no security headers)
    # - API9 hidden-path tests against 404 endpoints should NOT produce findings
    # - API1 BOLA tests would produce findings if they ran (path-param substitution returned 200)

    assert len(findings) > 0, "Expected at least some findings"

    categories_found = {f.category for f in findings}
    assert (
        "API8_MISCONFIGURATION" in categories_found
    ), "API8 should fire on missing headers"

    # Every finding has required fields
    for f in findings:
        assert f.title
        assert f.severity
        assert 0.0 <= f.confidence <= 1.0
        assert f.category
        assert "request" in f.evidence
        assert "response" in f.evidence


def test_pipeline_completes_within_reasonable_time(
    mock_server_handler, monkeypatch
):
    """Sanity check that the full scan completes in under 10 seconds."""
    import time

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(mock_server_handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(
        "core.api_security.execution.runner.httpx.AsyncClient", _PatchedClient
    )
    monkeypatch.setattr(
        "core.api_security.execution.orchestrator.save_scan",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "core.api_security.execution.orchestrator.log_audit",
        lambda *a, **kw: None,
    )

    spec = parse_spec(
        (FIXTURES / "petstore_openapi_3_0.json").read_bytes()
    )
    config = ScanConfig(
        target_base_url="https://api.staging.petstore.example.com/api/v1",
        concurrency=5,
        request_timeout_seconds=1.0,
        retry_attempts=0,
        use_llm_classification=False,
        use_llm_explanations=False,
    )
    orchestrator = ScanOrchestrator(config=config)

    start = time.perf_counter()
    list(orchestrator.run_scan(spec))
    elapsed = time.perf_counter() - start

    assert elapsed < 10.0, f"Scan took {elapsed:.1f}s — too slow"
