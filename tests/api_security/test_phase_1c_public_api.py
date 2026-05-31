"""Smoke tests for the Phase 1C public API."""


def test_public_imports():
    from core.api_security import (
        APISpec,
        AuthContext,
        Endpoint,
        GeneratorRegistry,
        HTTPMethod,
        OWASPAPICategory,
        ScanConfig,
        ScanOrchestrator,
        SecurityTest,
        parse_spec,
    )

    assert callable(parse_spec)
    assert APISpec is not None
    assert ScanOrchestrator is not None


def test_can_construct_orchestrator():
    from core.api_security import AuthContext, ScanConfig, ScanOrchestrator

    cfg = ScanConfig(target_base_url="https://api.staging.example.com")
    orchestrator = ScanOrchestrator(config=cfg, auth_context=AuthContext())
    assert orchestrator is not None
