"""Threat Analyzer: orquestra LLM (se houver) com fallback rule-based."""

from __future__ import annotations

import json
import re

from ..config import Settings, get_settings
from ..logging_setup import get_logger
from ..models import ThreatAnalysis, Vulnerability
from . import rules
from .adapter import build_adapter
from .prompts import SYSTEM_PROMPT, build_user_prompt

log = get_logger(__name__)


def _extract_json(text: str) -> dict | None:
    """Extrai o primeiro objeto JSON de um texto (tolera cercas de markdown)."""
    if not text:
        return None
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def _parse_analysis(data: dict, provider: str) -> ThreatAnalysis | None:
    """Valida o dict do LLM em ThreatAnalysis; retorna None se invalido."""
    try:
        return ThreatAnalysis(
            protocol=str(data.get("protocol", "unknown")),
            likely_attack_type=str(data.get("likely_attack_type", "unknown")),
            preconditions=str(data.get("preconditions", "")),
            expected_network_behavior=str(data.get("expected_network_behavior", "")),
            dataset_label=str(data.get("dataset_label", "unknown")),
            confidence=float(data.get("confidence", 0.5) or 0.5),
            safety_notes=str(data.get("safety_notes", "")),
            source=provider,
        )
    except (ValueError, TypeError) as exc:
        log.warning("Saida do LLM invalida (%s); caindo para rule-based.", exc)
        return None


def vuln_to_text(vuln: Vulnerability) -> str:
    """Serializa campos relevantes da vuln para o prompt/heuristica."""
    parts = [vuln.title, vuln.description, vuln.affected_product, vuln.cwe]
    return "\n".join(p for p in parts if p)


def analyze(text: str, protocol: str | None = None, settings: Settings | None = None) -> ThreatAnalysis:
    """Analisa um texto livre. Usa LLM se configurado, senao rule-based."""
    settings = settings or get_settings()
    adapter = build_adapter(settings)

    if adapter is not None:
        try:
            raw = adapter.complete(SYSTEM_PROMPT, build_user_prompt(text, protocol))
            data = _extract_json(raw)
            if data:
                parsed = _parse_analysis(data, settings.llm_provider)
                if parsed:
                    log.info("Analise via LLM (%s).", settings.llm_provider)
                    return parsed
            log.warning("LLM nao retornou JSON valido; usando rule-based.")
        except Exception as exc:  # rede, auth, etc. - degrade gracioso
            log.warning("Falha ao chamar LLM (%s); usando rule-based.", exc)

    return rules.analyze(text, protocol)


def analyze_vuln(vuln: Vulnerability, protocol: str | None = None,
                 settings: Settings | None = None) -> ThreatAnalysis:
    """Analisa uma Vulnerability."""
    return analyze(vuln_to_text(vuln), protocol=protocol, settings=settings)
