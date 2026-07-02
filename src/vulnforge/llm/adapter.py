"""LLM adapter for OpenRouter / local OpenAI-compatible endpoints."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import requests

from ..config import Settings, get_settings
from ..logging_setup import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    seed: int | None


class LLMAdapter:
    """Thin OpenAI-compatible chat completions adapter."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._session = requests.Session()

    @property
    def is_configured(self) -> bool:
        if self.settings.llm_provider == "offline":
            return False
        if self.settings.llm_provider == "openrouter" and not self.settings.openrouter_api_key:
            return False
        return True

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
        }
        if self.settings.llm_provider == "openrouter":
            headers["Authorization"] = f"Bearer {self.settings.openrouter_api_key}"
        return headers

    def _url(self) -> str:
        return self.settings.llm_base_url.rstrip("/") + "/chat/completions"

    def chat(
        self,
        system: str,
        user: str,
        temperature: float | None = None,
        seed: int | None = None,
        timeout: float = 60.0,
    ) -> LLMResponse:
        if not self.is_configured:
            raise RuntimeError("LLM adapter nao configurado; use modo offline.")

        temp = temperature if temperature is not None else self.settings.llm_temperature
        seed_value = seed if seed is not None else self.settings.llm_seed
        payload: dict[str, Any] = {
            "model": self.settings.llm_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temp,
            "seed": seed_value,
        }
        response = self._session.post(
            self._url(),
            headers=self._headers(),
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        choice = data["choices"][0]["message"]["content"]
        model = data.get("model", self.settings.llm_model)
        return LLMResponse(text=choice.strip(), model=model, seed=seed_value)

    def extract_json(self, text: str) -> dict[str, Any] | None:
        """Extract the first JSON object from text, tolerating markdown fences."""
        # Try fenced code block first.
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            candidate = match.group(1)
        else:
            match = re.search(r"(\{.*\})", text, re.DOTALL)
            if not match:
                return None
            candidate = match.group(1)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return None


def get_adapter(settings: Settings | None = None) -> LLMAdapter:
    return LLMAdapter(settings)
