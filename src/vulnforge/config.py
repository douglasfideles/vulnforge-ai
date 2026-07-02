"""Application configuration via pydantic-settings."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """VulnForge settings loaded from environment and .env files."""

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
        return Path(self.data_dir) / "datasets"

    @property
    def models_dir(self) -> Path:
        return Path(self.data_dir) / "models"

    @property
    def runs_dir(self) -> Path:
        return Path(self.data_dir) / "runs"

    @field_validator("llm_temperature")
    @classmethod
    def _clamp_temperature(cls, value: float) -> float:
        return max(0.0, min(2.0, float(value)))


@lru_cache
def get_settings() -> Settings:
    """Return a process-singleton Settings instance."""
    return Settings()
