"""Aggregates classifier outputs into Finding objects and computes scan summary."""

from collections import Counter

from core.api_security.execution.llm_classifier import LLMVerdict
from core.api_security.execution.llm_explainer import Explanation
from core.api_security.execution.models import ExecutionResult
from core.api_security.execution.rule_classifier import ClassificationOutcome
from core.api_security.test_models import SecurityTest
from core.logging_config import get_logger
from core.models import Finding, Severity

logger = get_logger("aggregator")


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Aggregator:
    """Builds Finding objects and computes scan summary."""

    def build_finding(
        self,
        test: SecurityTest,
        result: ExecutionResult,
        rule_outcome: ClassificationOutcome,
        llm_verdict: LLMVerdict | None = None,
        explanation: Explanation | None = None,
    ) -> Finding | None:
        """Build a Finding from classifier outputs, or None if not a vuln."""

        # Decide is_vulnerability + severity + confidence
        if llm_verdict is not None:
            # LLM tie-break has authority
            is_vuln = llm_verdict.is_vulnerability
            severity = llm_verdict.severity
            confidence = llm_verdict.confidence
            base_remediation = llm_verdict.suggested_remediation
        else:
            is_vuln = rule_outcome.is_vulnerability
            severity = rule_outcome.suggested_severity
            # Confidence: combine finding_score and rule_confidence
            confidence = (
                rule_outcome.finding_score + rule_outcome.rule_confidence
            ) / 2
            base_remediation = None

        if not is_vuln:
            return None

        # Build title and description from explanation if available
        if explanation:
            title = explanation.summary
            description = explanation.details
            remediation = explanation.remediation
        else:
            title = test.name
            description = test.rationale + (
                f"\n\nLLM analysis: {llm_verdict.explanation}"
                if llm_verdict
                else ""
            )
            remediation = base_remediation

        evidence = {
            "request": {
                "method": result.final_method.value,
                "url": result.final_url,
                "path": test.payload.path,
            },
            "response": {
                "http_status": result.http_status,
                "latency_ms": round(result.latency_ms, 1),
                "size_bytes": result.response_size_bytes,
                "body_excerpt": (result.response_body or "")[:500],
                "headers": dict(result.response_headers),
            },
            "rule_outcome": {
                "finding_score": round(rule_outcome.finding_score, 3),
                "rule_confidence": round(rule_outcome.rule_confidence, 3),
                "matched_indicators": [
                    {
                        "type": ind.type.value,
                        "weight": ind.weight,
                        "description": ind.description,
                    }
                    for ind in rule_outcome.matched_indicators
                ],
            },
        }
        if llm_verdict:
            evidence["llm_verdict"] = {
                "is_vulnerability": llm_verdict.is_vulnerability,
                "severity": llm_verdict.severity.value,
                "confidence": llm_verdict.confidence,
                "explanation": llm_verdict.explanation,
            }
        if explanation:
            evidence["references"] = explanation.references

        return Finding(
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            category=test.owasp_category.value,
            evidence=evidence,
            remediation=remediation,
        )

    def sort_findings(self, findings: list[Finding]) -> list[Finding]:
        """Sort findings: severity desc, then confidence desc, then category asc."""
        return sorted(
            findings,
            key=lambda f: (
                -SEVERITY_ORDER.get(f.severity, 0),
                -f.confidence,
                f.category,
            ),
        )

    def build_summary(
        self,
        findings: list[Finding],
        execution_results: list[ExecutionResult],
        total_tests: int,
    ) -> dict:
        severity_counts = Counter(f.severity.value for f in findings)
        category_counts = Counter(f.category for f in findings)
        exec_status_counts = Counter(r.status.value for r in execution_results)

        return {
            "total_tests_planned": total_tests,
            "total_tests_executed": len(execution_results),
            "total_findings": len(findings),
            "findings_by_severity": dict(severity_counts),
            "findings_by_category": dict(category_counts),
            "execution_status_counts": dict(exec_status_counts),
            "skipped_count": exec_status_counts.get("skipped", 0),
            "error_count": (
                exec_status_counts.get("timeout", 0)
                + exec_status_counts.get("network_error", 0)
            ),
        }
