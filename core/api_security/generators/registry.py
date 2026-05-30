"""Generator registry — runs all enabled generators against an APISpec."""

from core.api_security.generators.api1_bola import BOLAGenerator
from core.api_security.generators.api2_broken_auth import BrokenAuthGenerator
from core.api_security.generators.api3_property_auth import PropertyAuthGenerator
from core.api_security.generators.api4_resource_consumption import ResourceConsumptionGenerator
from core.api_security.generators.api5_function_auth import FunctionLevelAuthGenerator
from core.api_security.generators.api7_ssrf import SSRFGenerator
from core.api_security.generators.api8_misconfiguration import MisconfigurationGenerator
from core.api_security.generators.api9_inventory import InventoryGenerator
from core.api_security.generators.base import Generator
from core.api_security.generators.llm_helper import LLMPayloadHelper
from core.api_security.models import APISpec
from core.api_security.test_models import OWASPAPICategory, SecurityTest
from core.logging_config import get_logger

logger = get_logger("generator_registry")


# Default order — categories implemented in Phase 1
DEFAULT_GENERATOR_CLASSES = [
    BOLAGenerator,
    BrokenAuthGenerator,
    PropertyAuthGenerator,
    ResourceConsumptionGenerator,
    FunctionLevelAuthGenerator,
    SSRFGenerator,
    MisconfigurationGenerator,
    InventoryGenerator,
]


class GeneratorRegistry:
    """Holds and runs all enabled generators."""

    def __init__(
        self,
        *,
        use_llm: bool = False,
        llm_helper: LLMPayloadHelper | None = None,
        enabled_categories: set[OWASPAPICategory] | None = None,
    ):
        """
        Args:
            use_llm: Pass True to enable LLM-assisted payload generation.
            llm_helper: Helper instance. Required if use_llm=True.
            enabled_categories: If set, only generators for these categories run.
                                Default: all 8 phase-1 categories.
        """
        if use_llm and llm_helper is None:
            llm_helper = LLMPayloadHelper()

        self.use_llm = use_llm
        self.llm_helper = llm_helper
        self.enabled_categories = enabled_categories

        self.generators: list[Generator] = []
        for gen_class in DEFAULT_GENERATOR_CLASSES:
            instance = gen_class(use_llm=use_llm, llm_helper=llm_helper)
            if enabled_categories is not None and instance.category not in enabled_categories:
                continue
            self.generators.append(instance)

    def generate_all(self, spec: APISpec) -> list[SecurityTest]:
        """Run every enabled generator and return the combined list of tests."""
        all_tests: list[SecurityTest] = []
        for gen in self.generators:
            try:
                tests = gen.generate(spec)
                logger.info(
                    f"{gen.__class__.__name__} produced {len(tests)} tests for "
                    f"{spec.endpoint_count()} endpoints"
                )
                all_tests.extend(tests)
            except Exception as e:
                logger.error(f"Generator {gen.name} failed: {e}", exc_info=True)
                # continue with other generators rather than failing the whole scan
        return all_tests

    def tests_by_category(self, spec: APISpec) -> dict[OWASPAPICategory, list[SecurityTest]]:
        """Run all generators and return a dict keyed by category."""
        result: dict[OWASPAPICategory, list[SecurityTest]] = {}
        for gen in self.generators:
            try:
                result[gen.category] = gen.generate(spec)
            except Exception as e:
                logger.error(f"Generator {gen.name} failed: {e}", exc_info=True)
                result[gen.category] = []
        return result
