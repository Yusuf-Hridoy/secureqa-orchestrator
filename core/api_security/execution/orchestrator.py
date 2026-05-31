"""Top-level orchestrator: runs the full scan pipeline."""

import asyncio
from collections.abc import Iterator
from datetime import datetime

from core.api_security.execution.aggregator import Aggregator
from core.api_security.execution.auth_context import AuthContextResolver
from core.api_security.execution.llm_classifier import LLMClassifier
from core.api_security.execution.llm_explainer import LLMExplainer
from core.api_security.execution.models import (
    AuthContext,
    ExecutionResult,
    ExecutionStatus,
    ScanConfig,
)
from core.api_security.execution.rule_classifier import RuleBasedClassifier
from core.api_security.execution.runner import HTTPXRunner
from core.api_security.generators.registry import GeneratorRegistry
from core.api_security.models import APISpec
from core.api_security.test_models import SecurityTest
from core.logging_config import get_logger
from core.models import (
    AuditLogEntry,
    Finding,
    ScanProgress,
    ScanResult,
    ScanStatus,
    ScanType,
)
from core.safety import SafetyGuard
from core.storage import log_audit, save_scan

logger = get_logger("scan_orchestrator")


class ScanOrchestrator:
    """End-to-end scan orchestration."""

    def __init__(
        self,
        config: ScanConfig,
        auth_context: AuthContext | None = None,
        registry: GeneratorRegistry | None = None,
        rule_classifier: RuleBasedClassifier | None = None,
        llm_classifier: LLMClassifier | None = None,
        llm_explainer: LLMExplainer | None = None,
        aggregator: Aggregator | None = None,
        safety_guard: SafetyGuard | None = None,
    ):
        self.config = config
        self.auth_context = auth_context or AuthContext()
        self.registry = registry or GeneratorRegistry(use_llm=False)
        self.rule_classifier = rule_classifier or RuleBasedClassifier()
        self.llm_classifier = llm_classifier or (
            LLMClassifier() if config.use_llm_classification else None
        )
        self.llm_explainer = llm_explainer or (
            LLMExplainer() if config.use_llm_explanations else None
        )
        self.aggregator = aggregator or Aggregator()
        self.safety_guard = safety_guard or SafetyGuard()

    def run_scan(self, spec: APISpec) -> Iterator[ScanProgress]:
        """Generator yielding ScanProgress events.

        Last event includes the final ScanResult in ``partial_findings``.
        """
        started_at = datetime.utcnow()
        scan_result = ScanResult(
            scan_type=ScanType.API,
            target=self.config.target_base_url,
            status=ScanStatus.RUNNING,
            started_at=started_at,
            metadata={
                "spec_name": spec.name,
                "spec_endpoints": spec.endpoint_count(),
                "config": self.config.model_dump(
                    mode="json", exclude={"extra_headers"}
                ),
            },
        )

        # 1. SAFETY CHECK
        yield ScanProgress(
            step="safety_check",
            percent=2,
            message="Validating target safety...",
        )
        if not self.config.bypass_safety_guard:
            safety = self.safety_guard.validate_target(
                self.config.target_base_url
            )
            if not safety.allowed:
                log_audit(
                    AuditLogEntry(
                        event="scan_blocked",
                        target=self.config.target_base_url,
                        details={
                            "reason": safety.reason,
                            "is_production": safety.is_production,
                        },
                    )
                )
                scan_result.status = ScanStatus.BLOCKED
                scan_result.completed_at = datetime.utcnow()
                scan_result.summary = {"blocked_reason": safety.reason}
                save_scan(scan_result)
                self._last_scan_result = scan_result
                yield ScanProgress(
                    step="complete",
                    percent=100,
                    message=f"Scan blocked: {safety.reason}",
                )
                return

        # 2. AUDIT: scan started
        log_audit(
            AuditLogEntry(
                event="scan_started",
                target=self.config.target_base_url,
                details={
                    "scan_id": scan_result.scan_id,
                    "spec_name": spec.name,
                },
            )
        )

        # 3. GENERATE TESTS
        yield ScanProgress(
            step="generating_tests",
            percent=5,
            message="Generating security tests...",
        )
        try:
            tests: list[SecurityTest] = self.registry.generate_all(spec)
        except Exception as e:
            logger.error(f"Test generation failed: {e}", exc_info=True)
            scan_result.status = ScanStatus.FAILED
            scan_result.completed_at = datetime.utcnow()
            scan_result.metadata["error"] = f"Generation failed: {e}"
            save_scan(scan_result)
            self._last_scan_result = scan_result
            yield ScanProgress(
                step="complete", percent=100, message=f"Failed: {e}"
            )
            return

        yield ScanProgress(
            step="generating_tests",
            percent=15,
            message=f"Generated {len(tests)} tests across categories",
        )

        if not tests:
            scan_result.status = ScanStatus.COMPLETED
            scan_result.completed_at = datetime.utcnow()
            scan_result.summary = self.aggregator.build_summary(
                [], [], 0
            )
            save_scan(scan_result)
            self._last_scan_result = scan_result
            yield ScanProgress(
                step="complete",
                percent=100,
                message="No tests generated.",
            )
            return

        # 4. RESOLVE AUTH CONTEXT
        yield ScanProgress(
            step="resolving_auth",
            percent=20,
            message="Resolving auth context...",
        )
        resolver = AuthContextResolver(self.auth_context)
        resolved_tests: list[SecurityTest] = []
        skipped_results: list[ExecutionResult] = []
        for test in tests:
            res = resolver.resolve(test)
            if res.was_resolved:
                resolved_tests.append(res.resolved_test)
            else:
                skipped_results.append(
                    ExecutionResult(
                        test_id=test.test_id,
                        status=ExecutionStatus.SKIPPED,
                        skip_reason=res.skip_reason,
                        final_method=test.payload.method,
                    )
                )

        # 5. EXECUTE
        yield ScanProgress(
            step="executing",
            percent=25,
            message=f"Executing {len(resolved_tests)} tests "
            f"(concurrency={self.config.concurrency})...",
        )
        runner = HTTPXRunner(self.config)
        try:
            exec_results: list[ExecutionResult] = asyncio.run(
                asyncio.wait_for(
                    runner.run_batch(resolved_tests),
                    timeout=self.config.overall_timeout_seconds,
                )
            )
        except TimeoutError:
            logger.warning(
                "Scan exceeded overall timeout; returning partial results."
            )
            scan_result.metadata["timeout"] = True
            exec_results = []
        except Exception as e:
            logger.error(f"Runner failed: {e}", exc_info=True)
            scan_result.status = ScanStatus.FAILED
            scan_result.completed_at = datetime.utcnow()
            scan_result.metadata["error"] = f"Execution failed: {e}"
            save_scan(scan_result)
            self._last_scan_result = scan_result
            yield ScanProgress(
                step="complete", percent=100, message=f"Failed: {e}"
            )
            return

        # Merge in skipped results
        all_results = exec_results + skipped_results

        yield ScanProgress(
            step="executing",
            percent=70,
            message=f"Executed {len(exec_results)} tests, "
            f"skipped {len(skipped_results)}",
        )

        # 6. CLASSIFY + EXPLAIN
        yield ScanProgress(
            step="classifying",
            percent=75,
            message="Analyzing responses...",
        )
        findings: list[Finding] = []

        # Build a lookup: test_id → test
        test_by_id = {t.test_id: t for t in resolved_tests}

        for er in exec_results:
            test = test_by_id.get(er.test_id)
            if test is None:
                continue
            rule_outcome = self.rule_classifier.classify(test, er)
            if not rule_outcome.is_vulnerability:
                continue

            # LLM tie-break if rule is uncertain
            llm_verdict = None
            if (
                self.llm_classifier
                and rule_outcome.rule_confidence
                < self.config.llm_tie_break_threshold
            ):
                tb = self.llm_classifier.tie_break(test, er, rule_outcome)
                llm_verdict = tb.verdict

            # If LLM said it's NOT a vuln, skip
            if llm_verdict is not None and not llm_verdict.is_vulnerability:
                continue

            # Generate explanation
            severity = (
                llm_verdict.severity
                if llm_verdict
                else rule_outcome.suggested_severity
            )
            explanation = None
            if self.llm_explainer:
                exp_res = self.llm_explainer.explain(
                    test, er, rule_outcome, severity
                )
                explanation = exp_res.explanation

            finding = self.aggregator.build_finding(
                test,
                er,
                rule_outcome,
                llm_verdict=llm_verdict,
                explanation=explanation,
            )
            if finding is not None:
                findings.append(finding)

        # 7. AGGREGATE + SAVE
        yield ScanProgress(
            step="aggregating",
            percent=92,
            message="Building report...",
        )
        findings = self.aggregator.sort_findings(findings)
        summary = self.aggregator.build_summary(
            findings, all_results, total_tests=len(tests)
        )

        scan_result.findings = findings
        scan_result.summary = summary
        scan_result.status = ScanStatus.COMPLETED
        scan_result.completed_at = datetime.utcnow()
        save_scan(scan_result)
        log_audit(
            AuditLogEntry(
                event="scan_completed",
                target=self.config.target_base_url,
                details={
                    "scan_id": scan_result.scan_id,
                    "findings": len(findings),
                    "duration_s": (
                        scan_result.completed_at - scan_result.started_at
                    ).total_seconds(),
                },
            )
        )

        self._last_scan_result = scan_result
        yield ScanProgress(
            step="complete",
            percent=100,
            message=f"Scan complete: {len(findings)} findings.",
            partial_findings=findings,
        )

    def run_scan_blocking(self, spec: APISpec) -> ScanResult:
        """Convenience wrapper: drains the generator and returns the final ScanResult."""
        for _ in self.run_scan(spec):
            pass
        return getattr(self, "_last_scan_result", ScanResult(
            scan_type=ScanType.API,
            target=self.config.target_base_url,
            status=ScanStatus.FAILED,
        ))
