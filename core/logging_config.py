"""Loguru-based logging configuration for SecureQA Orchestrator."""

import sys
from pathlib import Path
from typing import Any

from loguru import logger

from config.settings import settings


def configure_logging() -> None:
    """Configure loguru with console and rotating file handlers.

    Removes default handlers, then adds:
    - Colorized stderr output
    - Compressed, rotated file output under ``settings.log_dir``
    """
    logger.remove()

    log_dir = Path(settings.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    fmt = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
        "{level: <8} | "
        "{name}:{function}:{line} - "
        "{message}"
    )

    logger.add(
        sys.stderr,
        level=settings.log_level,
        colorize=True,
        format=fmt,
    )

    log_path = log_dir / "secureqa_{time:YYYY-MM-DD}.log"
    logger.add(
        str(log_path),
        level=settings.log_level,
        rotation="10 MB",
        retention="7 days",
        compression="zip",
        format=fmt,
    )


def get_logger(name: str) -> Any:
    """Return a contextualized logger with ``name`` bound.

    Args:
        name: Logical component name (e.g. module ``__name__``).
    """
    return logger.bind(name=name)
