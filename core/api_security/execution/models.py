"""Models for the Phase 1C execution layer."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, SecretStr

from core.api_security.models import HTTPMethod


class ExecutionStatus(str, Enum):
    """Outcome of a single test execution."""

    SUCCESS = "success"  # request completed (any HTTP status)
    SKIPPED = "skipped"  # test could not run (e.g. missing auth context)
    TIMEOUT = "timeout"  # request timed out
    NETWORK_ERROR = "network_error"  # connection refused, DNS error, etc.
    BLOCKED = "blocked"  # safety guard refused this target


class AuthContext(BaseModel):
    """Optional auth tokens / values for placeholder substitution.

    Generators use placeholders like {{regular_user_token}}, {{userB_resource_id}}.
    The orchestrator resolves them using values from this context.
    If a placeholder has no matching key, the corresponding test is SKIPPED.
    """

    # Standard tokens (common cases)
    bearer_token: SecretStr | None = None
    regular_user_token: SecretStr | None = None  # for API5 tests
    admin_user_token: SecretStr | None = None  # for cross-tenant comparison
    user_a_token: SecretStr | None = None  # for BOLA cross-user tests
    user_b_token: SecretStr | None = None
    user_b_resource_id: str | None = None  # for BOLA cross-resource tests

    # API-key-style auth (header or query)
    api_key: SecretStr | None = None
    api_key_header_name: str = "X-API-Key"

    # Free-form extras for unusual placeholders
    extras: dict[str, str] = Field(default_factory=dict)

    def has_any_token(self) -> bool:
        return any(
            t is not None
            for t in (
                self.bearer_token,
                self.regular_user_token,
                self.user_a_token,
                self.user_b_token,
                self.api_key,
            )
        )


class ScanConfig(BaseModel):
    """Configuration for a single scan run."""

    # Targeting
    target_base_url: str  # explicit base URL — overrides spec base_url
    follow_redirects: bool = False

    # Concurrency + timing
    concurrency: int = Field(default=5, ge=1, le=20)
    request_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    overall_timeout_seconds: int = Field(default=600, ge=30, le=3600)  # 10 min default

    # Retry
    retry_attempts: int = Field(default=2, ge=0, le=5)
    retry_backoff_seconds: float = Field(default=1.0, ge=0.1)

    # LLM classification
    use_llm_classification: bool = True
    llm_tie_break_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    # LLM explanations
    use_llm_explanations: bool = True

    # Safety
    allow_destructive_methods: bool = False  # off by default — POST/PUT/PATCH/DELETE only if True
    bypass_safety_guard: bool = False  # NEVER True in normal use; for unit tests only

    # Misc
    user_agent: str = "SecureQA-Orchestrator/0.1 (security-scanner; +https://github.com/Yusuf-Hridoy/secureqa-orchestrator)"
    extra_headers: dict[str, str] = Field(default_factory=dict)  # added to every request


class ExecutionResult(BaseModel):
    """Raw result of executing one SecurityTest against the target."""

    test_id: str  # links back to SecurityTest.test_id
    status: ExecutionStatus
    http_status: int | None = None  # None if SKIPPED / TIMEOUT / NETWORK_ERROR
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""  # truncated to 256 KB max
    response_size_bytes: int = 0
    latency_ms: float = 0.0
    error_message: str | None = None
    skip_reason: str | None = None  # populated if status == SKIPPED
    final_url: str = ""  # URL actually requested (after path/param resolution)
    final_method: HTTPMethod = HTTPMethod.GET
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


# Max response body capture (256 KB)
MAX_RESPONSE_BODY_BYTES = 256 * 1024
