"""Adapters de LLM: interface comum + OpenRouter + servidor local (OpenAI-compativel)."""

from __future__ import annotations

import json
from typing import Protocol

import requests

from ..config import Settings
from ..logging_setup import get_logger

log = get_logger(__name__)


class LLMAdapter(Protocol):
    """Interface minima: dado system+user prompt, retorna texto."""

    def complete(self, system_prompt: str, user_prompt: str) -> str: ...


class _OpenAICompatibleAdapter:
    """Chat completions compativel com OpenAI (OpenRouter, Ollama, llama.cpp...)."""

    def __init__(
        self, base_url: str, api_key: str, model: str,
        temperature: float = 0.0, seed: int | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.seed = seed

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
        }
        if self.seed is not None:
            payload["seed"] = self.seed  # reprodutibilidade (suportado por varios backends)
        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            data=json.dumps(payload),
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


def build_adapter(settings: Settings) -> LLMAdapter | None:
    """Constroi o adapter conforme settings. Retorna None para modo offline."""
    provider = settings.llm_provider.lower()
    if provider == "offline":
        return None
    if provider == "openrouter":
        if not settings.openrouter_api_key:
            log.info("OPENROUTER_API_KEY ausente; usando modo rule-based offline.")
            return None
        return _OpenAICompatibleAdapter(
            settings.llm_base_url, settings.openrouter_api_key, settings.llm_model,
            temperature=settings.llm_temperature, seed=settings.llm_seed,
        )
    if provider == "local":
        return _OpenAICompatibleAdapter(
            settings.llm_base_url, settings.openrouter_api_key, settings.llm_model,
            temperature=settings.llm_temperature, seed=settings.llm_seed,
        )
    log.warning("Provider LLM desconhecido '%s'; usando offline.", provider)
    return None
