"""Phase 1C — Execution layer.

Public API:
    from core.api_security.execution import ScanOrchestrator, ScanConfig, AuthContext
"""

from core.api_security.execution.aggregator import Aggregator
from core.api_security.execution.auth_context import AuthContextResolver
from core.api_security.execution.llm_classifier import LLMClassifier, LLMVerdict
from core.api_security.execution.llm_explainer import Explanation, LLMExplainer
from core.api_security.execution.models import (
    AuthContext,
    ExecutionResult,
    ExecutionStatus,
    ScanConfig,
)
from core.api_security.execution.orchestrator import ScanOrchestrator
from core.api_security.execution.rule_classifier import (
    ClassificationOutcome,
    RuleBasedClassifier,
)
from core.api_security.execution.runner import HTTPXRunner

__all__ = [
    # Top-level entry
    "ScanOrchestrator",
    # Config & context
    "ScanConfig",
    "AuthContext",
    # Results
    "ExecutionResult",
    "ExecutionStatus",
    # Components (advanced usage)
    "HTTPXRunner",
    "RuleBasedClassifier",
    "ClassificationOutcome",
    "LLMClassifier",
    "LLMVerdict",
    "LLMExplainer",
    "Explanation",
    "AuthContextResolver",
    "Aggregator",
]
