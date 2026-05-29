"""Abstract base class for scan result exporters."""

from abc import ABC, abstractmethod
from typing import Any

from core.models import ScanResult


class Exporter(ABC):
    """Base class for all exporters."""

    name: str = "base"

    @abstractmethod
    def export(self, result: ScanResult) -> Any:
        """Export a scan result. Returns format-specific output."""
        ...
