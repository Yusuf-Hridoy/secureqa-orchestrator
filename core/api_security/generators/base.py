"""Abstract base class for OWASP API security test generators."""

from abc import ABC, abstractmethod

from core.api_security.models import APISpec
from core.api_security.test_models import OWASPAPICategory, SecurityTest


class Generator(ABC):
    """Base class for all OWASP API category generators.

    Generators are PURE PLANNERS:
    - Input: APISpec
    - Output: list[SecurityTest]
    - MUST NOT make HTTP calls
    - MUST NOT mutate the input APISpec
    - Should be deterministic for rule-based output
    """

    category: OWASPAPICategory
    name: str

    def __init__(self, *, use_llm: bool = False, llm_helper=None):
        """
        Args:
            use_llm: If True, generator may invoke the LLM helper for creative payloads.
            llm_helper: Instance of LLMPayloadHelper. Required if use_llm=True.
        """
        self.use_llm = use_llm
        self.llm_helper = llm_helper
        if use_llm and llm_helper is None:
            raise ValueError("llm_helper is required when use_llm=True")

    @abstractmethod
    def generate(self, spec: APISpec) -> list[SecurityTest]:
        """Generate security tests for the given API spec."""
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} category={self.category.value}>"
