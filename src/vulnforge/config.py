"""Configuracao central, carregada de variaveis de ambiente / .env."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings do VulnForge. Prefixo VULNFORGE_, exceto OPENROUTER_API_KEY."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="VULNFORGE_",
        extra="ignore",
    )

    # LLM
    llm_provider: str = "openrouter"  # openrouter | local | offline
    llm_model: str = "anthropic/claude-sonnet-4"
    llm_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_api_key: str = ""
    # Reprodutibilidade (importante p/ metodologia academica)
    llm_temperature: float = 0.0
    llm_seed: int = 1337

    # Armazenamento
    db_path: Path = Path("data/vulnforge.db")
    data_dir: Path = Path("data")

    # Logging
    log_level: str = "INFO"

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        # OPENROUTER_API_KEY nao usa prefixo VULNFORGE_; le diretamente.
        import os

        if not self.openrouter_api_key:
            self.openrouter_api_key = os.environ.get("OPENROUTER_API_KEY", "")

    @property
    def datasets_dir(self) -> Path:
        return self.data_dir / "datasets"

    @property
    def models_dir(self) -> Path:
        return self.data_dir / "models"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"


_settings: Settings | None = None


def get_settings() -> Settings:
    """Singleton simples das settings."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
