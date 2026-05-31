"""Tests for ScanOrchestrator. All HTTP and LLM are mocked."""


import httpx
import pytest

from core.api_security.execution.models import ScanConfig
from core.api_security.execution.orchestrator import ScanOrchestrator
from core.api_security.models import APISpec, SpecFormat


@pytest.fixture
def empty_spec():
    return APISpec(name="Test", source_format=SpecFormat.OPENAPI_3_0)


@pytest.fixture
def cfg():
    return ScanConfig(
        target_base_url="https://api.staging.example.com",
        concurrency=2,
        request_timeout_seconds=1.0,
        retry_attempts=0,
        use_llm_classification=False,
        use_llm_explanations=False,
        bypass_safety_guard=False,
    )


@pytest.fixture
def cfg_bypass():
    return ScanConfig(
        target_base_url="https://api.staging.example.com",
        concurrency=2,
        request_timeout_seconds=1.0,
        retry_attempts=0,
        use_llm_classification=False,
        use_llm_explanations=False,
        bypass_safety_guard=True,
    )


def test_blocked_target_returns_blocked_status(monkeypatch, empty_spec):
    cfg = ScanConfig(target_base_url="https://api.production.example.com")
    orchestrator = ScanOrchestrator(config=cfg)

    progress_events = list(orchestrator.run_scan(empty_spec))
    # Last event = complete with blocked
    assert any("blocked" in p.message.lower() for p in progress_events)


def test_completes_with_empty_spec(monkeypatch, empty_spec, cfg_bypass):
    """Empty spec → still completes (API9 probes hidden paths)."""

    def handler(req):
        return httpx.Response(404)

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
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

    orchestrator = ScanOrchestrator(config=cfg_bypass)
    events = list(orchestrator.run_scan(empty_spec))
    final = events[-1]
    assert final.step == "complete"
    assert final.percent == 100


def test_progress_events_emitted_in_order(monkeypatch, empty_spec, cfg_bypass):
    def handler(req):
        return httpx.Response(404)

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
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

    orchestrator = ScanOrchestrator(config=cfg_bypass)
    events = list(orchestrator.run_scan(empty_spec))

    steps_seen = [e.step for e in events]
    # Expected lifecycle: safety_check → generating_tests (×N) → resolving_auth → executing → classifying → aggregating → complete
    assert steps_seen[0] == "safety_check"
    assert steps_seen[-1] == "complete"


def test_findings_returned_for_missing_security_headers(monkeypatch, cfg_bypass):
    """Server returns 200 with no security headers → API8 should fire."""
    from core.api_security.models import (
        APISpec,
        Endpoint,
        HTTPMethod,
        SpecFormat,
    )
    from core.api_security.models import (
        Response as RespModel,
    )

    spec = APISpec(
        name="X",
        source_format=SpecFormat.OPENAPI_3_0,
        endpoints=[
            Endpoint(
                path="/health",
                method=HTTPMethod.GET,
                responses={"200": RespModel(status_code="200")},
            )
        ],
    )

    def handler(req):
        return httpx.Response(200, content=b'{"ok":true}')  # no security headers

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
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

    orchestrator = ScanOrchestrator(config=cfg_bypass)
    events = list(orchestrator.run_scan(spec))
    final = events[-1]
    assert final.step == "complete"
    # API8 should have flagged missing security headers
    assert len(final.partial_findings) > 0
    assert any("API8" in f.category for f in final.partial_findings)
