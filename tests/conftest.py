"""Shared pytest fixtures for SecureQA Orchestrator tests."""

from datetime import datetime
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.models import (
    Finding,
    ScanResult,
    ScanStatus,
    ScanType,
    Severity,
)


@pytest.fixture
def in_memory_engine():
    """Provide an in-memory SQLite engine for isolated DB tests."""
    from core.storage import Base  # noqa: import inside fixture to avoid circular
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(in_memory_engine):
    """Provide a SQLAlchemy session against the in-memory DB."""
    with Session(in_memory_engine) as session:
        yield session


@pytest.fixture
def sample_finding() -> Finding:
    """A sample Finding for use in tests."""
    return Finding(
        title="Test BOLA finding",
        description="User can access another user's resource by changing the ID.",
        severity=Severity.HIGH,
        confidence=0.85,
        category="OWASP_API_01_BOLA",
        evidence={"request": "GET /users/2", "response_code": 200},
        remediation="Add authorization check on resource ownership.",
    )


@pytest.fixture
def sample_scan_result(sample_finding) -> ScanResult:
    """A sample ScanResult for use in tests."""
    return ScanResult(
        scan_type=ScanType.API,
        target="https://api.staging.example.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, 10, 0, 0),
        completed_at=datetime(2026, 1, 1, 10, 5, 0),
        findings=[sample_finding],
    )


@pytest.fixture
def mock_gemini_response():
    """A mock Gemini API response."""
    mock = MagicMock()
    mock.text = "Mocked Gemini response"
    return mock


@pytest.fixture
def mock_genai_model(mocker, mock_gemini_response):
    """Mock the google.generativeai GenerativeModel class."""
    mock_model = MagicMock()
    mock_model.generate_content.return_value = mock_gemini_response
    mocker.patch("google.generativeai.GenerativeModel", return_value=mock_model)
    mocker.patch("google.generativeai.configure")
    return mock_model
