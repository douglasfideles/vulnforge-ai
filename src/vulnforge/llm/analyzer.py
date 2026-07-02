from __future__ import annotations

import json
import logging
from json import JSONDecoder

import requests

from vulnforge.config import Settings, get_settings
from vulnforge.models import ThreatAnalysis
from .rules import analyze_rules

log = logging.getLogger(__name__)


def _first_json(text: str) -> dict:
    decoder = JSONDecoder()
    for index, char in enumerate(text):
        if char == "{":
            try:
                obj, _ = decoder.raw_decode(text[index:])
                return obj
            except json.JSONDecodeError:
                pass
    raise ValueError("No JSON object in model response")


def analyze(text: str, protocol: str = "", settings: Settings | None = None) -> ThreatAnalysis:
    cfg = settings or get_settings()
    provider = cfg.llm_provider.lower()
    if provider == "offline" or (provider == "openrouter" and not cfg.openrouter_api_key):
        return analyze_rules(text, protocol)
    try:
        headers = {"Content-Type": "application/json"}
        if provider == "openrouter":
            headers["Authorization"] = f"Bearer {cfg.openrouter_api_key}"
        prompt = (
            "Return only JSON matching fields protocol, likely_attack_type, preconditions, "
            "expected_network_behavior, dataset_label, confidence, safety_notes. "
            f"Protocol hint: {protocol or 'none'}. Vulnerability: {text}"
        )
        response = requests.post(
            cfg.llm_base_url.rstrip("/") + "/chat/completions",
            headers=headers,
            json={
                "model": cfg.llm_model,
                "temperature": cfg.llm_temperature,
                "seed": cfg.llm_seed,
                "messages": [
                    {"role": "system", "content": "Analyze controlled IoT lab threats; never generate exploit networking code."},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=30,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return ThreatAnalysis(**_first_json(content), source=provider)
    except Exception as exc:
        log.warning("LLM analysis failed; using deterministic rules: %s", exc)
        return analyze_rules(text, protocol)

