"""Application settings loaded from environment variables via pydantic-settings.

This module defines the canonical configuration schema for SecureQA Orchestrator
and exposes a singleton ``settings`` instance for import-time use, plus a
``get_settings()`` factory for dependency injection (e.g. FastAPI).
"""

from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Orchestrator configuration backed by environment variables."""

    # API Keys
    gemini_api_key: SecretStr
    clickup_api_key: SecretStr | None = None

    # LLM
    gemini_model: str = "gemini-2.5-flash-lite"
    llm_temperature: float = 0.2
    llm_max_tokens: int = 4096
    llm_timeout_seconds: int = 30

    # Storage
    db_path: str = "data/scans.db"
    log_dir: str = "data/logs"
    log_level: str = "INFO"

    # Safety
    allowlist_path: str = "config/target_allowlist.json"
    block_production: bool = True

    # App
    app_name: str = "SecureQA Orchestrator"
    environment: Literal["development", "staging", "production"] = "development"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


# Singleton instance for import-time convenience
settings = Settings()


def get_settings() -> Settings:
    """Return the settings singleton.

    Intended for use with dependency injection frameworks such as FastAPI's
    ``Depends`` system.
    """
    return settings
