"""Exceptions for the API Security Validator spec ingestion layer."""


class SpecParseError(Exception):
    """Raised when a spec file cannot be parsed or validated.

    Attributes:
        message: Human-readable error description.
        line_number: Optional source line number for actionable feedback.
        source: Optional file path or origin identifier.
    """

    def __init__(
        self,
        message: str,
        *,
        line_number: int | None = None,
        source: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.line_number = line_number
        self.source = source

    def __str__(self) -> str:
        parts = [self.message]
        if self.line_number is not None:
            parts.append(f"(line {self.line_number})")
        if self.source is not None:
            parts.append(f"[{self.source}]")
        return " ".join(parts)


class UnsupportedSpecError(Exception):
    """Raised when the uploaded file format is not OpenAPI or Postman."""

    def __init__(self, message: str, *, detected_format: str | None = None) -> None:
        super().__init__(message)
        self.detected_format = detected_format


class RefResolutionError(SpecParseError):
    """Raised when an internal or external $ref cannot be resolved."""

    def __init__(self, message: str, *, ref: str | None = None) -> None:
        super().__init__(message)
        self.ref = ref
