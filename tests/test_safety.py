"""Tests for the safety guard."""

import json

import pytest

from core.safety import SafetyGuard


@pytest.fixture
def guard(tmp_path):
    """SafetyGuard backed by a temporary allowlist."""
    allowlist = {
        "allowed_patterns": [
            "*.staging.*",
            "*.dev.*",
            "localhost",
            "localhost:*",
            "127.0.0.1",
            "127.0.0.1:*",
            "dev-*",
            "*.example.com",
        ],
        "blocked_patterns": [
            "*.prod.*",
            "*production*",
            "*.live",
            "www.*",
        ],
    }
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps(allowlist))
    return SafetyGuard(allowlist_path=str(path))


def test_staging_url_allowed(guard: SafetyGuard) -> None:
    """Staging URLs in the allowlist should pass validation."""
    result = guard.validate_target("https://api.staging.example.com")
    assert result.allowed is True
    assert result.is_production is False


def test_dev_url_allowed(guard: SafetyGuard) -> None:
    """Dev URLs in the allowlist should pass validation."""
    result = guard.validate_target("https://dev-api.example.com")
    assert result.allowed is True
    assert result.is_production is False


def test_localhost_allowed(guard: SafetyGuard) -> None:
    """Localhost URLs should pass validation."""
    result = guard.validate_target("http://localhost:8000")
    assert result.allowed is True
    assert result.is_production is False


def test_production_url_blocked(guard: SafetyGuard) -> None:
    """Production URLs should be blocked and flagged as production."""
    result = guard.validate_target("https://api.production.example.com")
    assert result.allowed is False
    assert result.is_production is True


def test_www_blocked(guard: SafetyGuard) -> None:
    """www hostnames should be blocked by the denylist."""
    result = guard.validate_target("https://www.example.com")
    assert result.allowed is False


def test_url_encoded_bypass_blocked(guard: SafetyGuard) -> None:
    """URL-encoded bypass attempts should still match blocked patterns."""
    result = guard.validate_target("https://api.%70roduction.example.com")
    assert result.allowed is False


def test_audit_log_entry_created(guard: SafetyGuard, mocker) -> None:
    """validate_target should log an audit entry for every outcome."""
    mock_log = mocker.patch("core.safety.log_audit")
    result = guard.validate_target("https://api.staging.example.com")
    assert result.allowed is True
    mock_log.assert_called_once()
    entry = mock_log.call_args[0][0]
    assert entry.event == "target_validated"
    assert entry.target == "api.staging.example.com"


def test_blocked_takes_precedence_over_allowed(tmp_path) -> None:
    """A URL matching both allowed and blocked patterns must be blocked."""
    allowlist = {
        "allowed_patterns": ["*.example.com"],
        "blocked_patterns": ["www.*"],
    }
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps(allowlist))
    guard = SafetyGuard(allowlist_path=str(path))
    result = guard.validate_target("https://www.example.com")
    assert result.allowed is False
    assert "blocked" in result.reason.lower()
