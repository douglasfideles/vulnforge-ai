from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VULNFORGE_", env_file=".env", extra="ignore"
    )
    llm_provider: str = "openrouter"
    llm_model: str = "anthropic/claude-sonnet-4"
    llm_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_api_key: str = Field("", validation_alias="OPENROUTER_API_KEY")
    llm_temperature: float = 0.0
    llm_seed: int = 1337
    db_path: Path = Path("data/vulnforge.db")
    data_dir: Path = Path("data")
    log_level: str = "INFO"

    @property
    def datasets_dir(self) -> Path:
        return self.data_dir / "datasets"

    @property
    def models_dir(self) -> Path:
        return self.data_dir / "models"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"


@lru_cache
def get_settings() -> Settings:
    return Settings()
