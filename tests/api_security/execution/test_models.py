"""Tests for Phase 1C execution models."""

import pytest
from pydantic import ValidationError

from core.api_security.execution.models import (
    AuthContext,
    ExecutionResult,
    ExecutionStatus,
    ScanConfig,
)


def test_scan_config_defaults():
    cfg = ScanConfig(target_base_url="https://api.staging.example.com")
    assert cfg.concurrency == 5
    assert cfg.request_timeout_seconds == 10.0
    assert cfg.use_llm_classification is True
    assert cfg.allow_destructive_methods is False


def test_scan_config_concurrency_validation():
    with pytest.raises(ValidationError):
        ScanConfig(target_base_url="https://x.example.com", concurrency=0)
    with pytest.raises(ValidationError):
        ScanConfig(target_base_url="https://x.example.com", concurrency=25)


def test_scan_config_timeout_validation():
    with pytest.raises(ValidationError):
        ScanConfig(target_base_url="https://x.example.com", request_timeout_seconds=0)


def test_auth_context_empty_has_no_tokens():
    ctx = AuthContext()
    assert ctx.has_any_token() is False


def test_auth_context_with_bearer():
    ctx = AuthContext(bearer_token="abc123")
    assert ctx.has_any_token() is True


def test_auth_context_secrets_hidden_in_repr():
    ctx = AuthContext(bearer_token="super-secret-token")
    assert "super-secret-token" not in repr(ctx)


def test_execution_result_minimal():
    r = ExecutionResult(test_id="test-1", status=ExecutionStatus.SUCCESS)
    assert r.test_id == "test-1"
    assert r.status == ExecutionStatus.SUCCESS
    assert r.http_status is None


def test_execution_result_with_response():
    r = ExecutionResult(
        test_id="test-1",
        status=ExecutionStatus.SUCCESS,
        http_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"ok": true}',
        response_size_bytes=12,
        latency_ms=123.4,
    )
    assert r.http_status == 200
    assert r.response_headers["Content-Type"] == "application/json"


def test_execution_status_enum_values():
    assert ExecutionStatus.SUCCESS.value == "success"
    assert ExecutionStatus.SKIPPED.value == "skipped"
    assert ExecutionStatus.BLOCKED.value == "blocked"
