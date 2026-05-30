"""API Security Validator — Phase 1 of SecureQA Orchestrator.

Public API:
    from core.api_security import parse_spec, APISpec, GeneratorRegistry
"""

from core.api_security.generators import GeneratorRegistry
from core.api_security.models import APISpec, Endpoint, HTTPMethod
from core.api_security.parsers.auto_detect import detect_format, parse_spec
from core.api_security.test_models import OWASPAPICategory, SecurityTest

__all__ = [
    "parse_spec",
    "detect_format",
    "APISpec",
    "Endpoint",
    "HTTPMethod",
    "GeneratorRegistry",
    "OWASPAPICategory",
    "SecurityTest",
]
