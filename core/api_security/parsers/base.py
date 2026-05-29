"""Abstract base class for API spec parsers."""

from abc import ABC, abstractmethod

from core.api_security.models import APISpec, ParseWarning


class SpecParser(ABC):
    """Base class for all spec parsers (OpenAPI, Postman, etc.)."""

    name: str = "base"
    supported_formats: tuple[str, ...] = ()  # e.g., ("json", "yaml")

    def __init__(self, *, lenient: bool = False):
        """
        Args:
            lenient: If True, parse what's valid and collect errors as warnings.
                     If False (default), raise SpecParseError on any malformed input.
        """
        self.lenient = lenient
        self._warnings: list[ParseWarning] = []

    @abstractmethod
    def can_parse(self, content: dict | str | bytes) -> bool:
        """Return True if this parser can handle the given content."""
        ...

    @abstractmethod
    def parse(self, content: dict | str | bytes) -> APISpec:
        """Parse the content into an APISpec.

        Raises:
            SpecParseError: If content is malformed (strict mode).
            UnsupportedSpecError: If content format is not supported.
        """
        ...

    def _add_warning(
        self, code: str, message: str, location: str | None = None
    ) -> None:
        """Record a parse warning (used in lenient mode and for soft errors)."""
        self._warnings.append(
            ParseWarning(code=code, message=message, location=location)
        )

    def _ensure_dict(self, content: dict | str | bytes) -> dict:
        """Normalize input to a dict (parse JSON or YAML if needed)."""
        if isinstance(content, dict):
            return content
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        if isinstance(content, str):
            # Try JSON first, fall back to YAML
            import json

            import yaml

            try:
                return json.loads(content)
            except json.JSONDecodeError:
                try:
                    result = yaml.safe_load(content)
                    if not isinstance(result, dict):
                        raise ValueError("Parsed content is not a dict")
                    return result
                except yaml.YAMLError as e:
                    from core.api_security.exceptions import SpecParseError

                    raise SpecParseError(
                        f"Content is neither valid JSON nor YAML: {e}"
                    ) from e
        from core.api_security.exceptions import SpecParseError

        raise SpecParseError(
            f"Unsupported content type: {type(content).__name__}"
        )
