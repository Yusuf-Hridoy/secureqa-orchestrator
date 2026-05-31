"""Fixtures for execution tests. All HTTP is mocked via httpx.MockTransport."""

import httpx
import pytest

from core.api_security.execution.models import ScanConfig
from core.api_security.models import HTTPMethod
from core.api_security.test_models import (
    OWASPAPICategory,
    SecurityTest,
    TestPayload,
)


@pytest.fixture
def scan_config():
    return ScanConfig(
        target_base_url="https://api.staging.example.com",
        concurrency=3,
        request_timeout_seconds=2.0,
        retry_attempts=0,  # tests are deterministic, no retry by default
    )


@pytest.fixture
def scan_config_with_destructive_allowed():
    return ScanConfig(
        target_base_url="https://api.staging.example.com",
        concurrency=3,
        request_timeout_seconds=2.0,
        retry_attempts=0,
        allow_destructive_methods=True,
    )


def make_test(method=HTTPMethod.GET, path="/health", body=None, headers=None):
    return SecurityTest(
        owasp_category=OWASPAPICategory.API8_MISCONFIGURATION,
        name=f"test-{method.value}-{path}",
        description="x",
        rationale="x",
        target_endpoint_path=path,
        target_endpoint_method=method,
        payload=TestPayload(
            method=method,
            path=path,
            body=body,
            headers=headers or {},
        ),
    )


@pytest.fixture
def get_test():
    return make_test(HTTPMethod.GET, "/health")


@pytest.fixture
def post_test():
    return make_test(HTTPMethod.POST, "/users", body={"name": "test"})


def make_mock_transport(handler):
    """Build a httpx.MockTransport with the given handler."""
    return httpx.MockTransport(handler)
