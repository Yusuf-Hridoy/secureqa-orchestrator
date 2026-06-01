"""Pure-function filters for the findings table."""

from core.models import Finding, Severity


def filter_findings(
    findings: list[Finding],
    *,
    severities: set[Severity] | None = None,
    categories: set[str] | None = None,
    min_confidence: float | None = None,
    search_text: str | None = None,
) -> list[Finding]:
    """Filter findings by severity, category, confidence, and free text.

    All filters are AND'd. None means "don't filter on this dimension".
    """
    result = list(findings)

    if severities:
        result = [f for f in result if f.severity in severities]
    if categories:
        result = [f for f in result if f.category in categories]
    if min_confidence is not None:
        result = [f for f in result if f.confidence >= min_confidence]
    if search_text:
        needle = search_text.lower()
        result = [
            f for f in result
            if needle in f.title.lower()
            or needle in f.description.lower()
            or needle in f.category.lower()
        ]

    return result
