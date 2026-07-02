"""Application configuration via pydantic-settings.

Settings are loaded from environment variables and `.env` files.
All VULNFORGE_* prefixed keys are recognized, except OPENROUTER_API_KEY
which is read without prefix for compatibility with common setups.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """VulnForge settings loaded from environment and `.env` files.

    Attributes:
        llm_provider: One of ``openrouter``, ``local`` or ``offline``.
        llm_model: Model identifier passed to the OpenAI-compatible endpoint.
        llm_base_url: Base URL for the chat completions endpoint.
        openrouter_api_key: API key for OpenRouter (read without VULNFORGE_ prefix).
        llm_temperature: Sampling temperature, clamped to [0, 2].
        llm_seed: Fixed seed for deterministic LLM calls.
        db_path: Path to the SQLite database.
        data_dir: Root directory for generated artifacts.
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
    """

    model_config = SettingsConfigDict(
        env_prefix="VULNFORGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    llm_provider: str = "openrouter"  # openrouter | local | offline
    llm_model: str = "anthropic/claude-sonnet-4"
    llm_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_api_key: str = ""
    llm_temperature: float = 0.0
    llm_seed: int = 1337

    db_path: str = "data/vulnforge.db"
    data_dir: str = "data"
    log_level: str = "INFO"

    @property
    def datasets_dir(self) -> Path:
        """Directory where labeled datasets are stored."""
        return Path(self.data_dir) / "datasets"

    @property
    def models_dir(self) -> Path:
        """Directory where trained IDS models are stored."""
        return Path(self.data_dir) / "models"

    @property
    def runs_dir(self) -> Path:
        """Directory where run artifacts (pcap, yaml, logs) are stored."""
        return Path(self.data_dir) / "runs"

    @field_validator("llm_temperature")
    @classmethod
    def _clamp_temperature(cls, value: float) -> float:
        """Clamp temperature to the valid [0, 2] interval."""
        return max(0.0, min(2.0, float(value)))


@lru_cache
def get_settings() -> Settings:
    """Return a process-singleton Settings instance."""
    return Settings()
