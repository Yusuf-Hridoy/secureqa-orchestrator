"""Format auto-detection and dispatch to the correct parser."""

from core.api_security.exceptions import UnsupportedSpecError
from core.api_security.models import APISpec
from core.api_security.parsers.base import SpecParser
from core.api_security.parsers.openapi_parser import OpenAPIParser
from core.api_security.parsers.postman_parser import PostmanParser
from core.logging_config import get_logger

logger = get_logger("auto_detect")


def get_available_parsers(lenient: bool = False) -> list[SpecParser]:
    """Return all available parsers, in priority order."""
    return [
        OpenAPIParser(lenient=lenient),
        PostmanParser(lenient=lenient),
    ]


def detect_format(
    content: dict | str | bytes, lenient: bool = False
) -> SpecParser | None:
    """Return the first parser that can handle this content, or None."""
    parsers = get_available_parsers(lenient=lenient)
    for parser in parsers:
        try:
            if parser.can_parse(content):
                logger.info(f"Auto-detected format: {parser.name}")
                return parser
        except Exception as e:
            logger.debug(f"Parser {parser.name} can_parse raised: {e}")
    return None


def parse_spec(
    content: dict | str | bytes, *, lenient: bool = False
) -> APISpec:
    """Parse content using the appropriate parser based on content sniffing.

    Args:
        content: Spec content as dict (already parsed), str (JSON/YAML text),
                 or bytes (raw file content).
        lenient: If True, collect parse errors as warnings instead of raising.

    Returns:
        APISpec: Normalized internal representation.

    Raises:
        UnsupportedSpecError: If no parser recognizes the format.
        SpecParseError: If the content is malformed (strict mode).
    """
    parser = detect_format(content, lenient=lenient)
    if parser is None:
        raise UnsupportedSpecError(
            "Could not auto-detect spec format. "
            "Supported formats: OpenAPI 3.0/3.1 (JSON/YAML), Postman Collection v2.1 (JSON)."
        )
    return parser.parse(content)
