"""Tests for settings."""

from vulnforge.config import Settings


def test_defaults():
    s = Settings()
    assert s.llm_provider == "openrouter"
    assert s.llm_seed == 1337
    assert s.datasets_dir.name == "datasets"


def test_temperature_clamp():
    s = Settings(llm_temperature=5.0)
    assert s.llm_temperature == 2.0
