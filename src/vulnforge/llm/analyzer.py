"""Threat analyzer orchestrator with LLM + rule-based fallback."""

from __future__ import annotations

import json

from ..config import Settings, get_settings
from ..logging_setup import get_logger
from ..models import ThreatAnalysis, Vulnerability
from .adapter import LLMAdapter, get_adapter
from .prompts import ANALYSIS_SYSTEM_PROMPT, analysis_user_prompt
from .rules import analyze as rules_analyze

logger = get_logger(__name__)


def vuln_to_text(vuln: Vulnerability) -> str:
    """Convert a Vulnerability record into analysis input text."""
    parts = [
        f"ID: {vuln.id}",
        f"Title: {vuln.title}",
        f"Description: {vuln.description}",
    ]
    if vuln.cvss is not None:
        parts.append(f"CVSS: {vuln.cvss}")
    if vuln.affected_product:
        parts.append(f"Affected product: {vuln.affected_product}")
    return "\n".join(parts)


def _coerce_analysis(raw: dict, source: str, model: str = "", seed: int | None = None) -> ThreatAnalysis:
    from ..models import AttackType
    attack_value = raw.get("likely_attack_type", "unknown")
    try:
        attack_type = AttackType(attack_value)
    except ValueError:
        attack_type = AttackType.UNKNOWN
    return ThreatAnalysis(
        protocol=raw.get("protocol", "unknown"),
        likely_attack_type=attack_type,
        preconditions=raw.get("preconditions", ""),
        expected_network_behavior=raw.get("expected_network_behavior", ""),
        dataset_label=raw.get("dataset_label", "unknown"),
        confidence=float(raw.get("confidence", 0.0)),
        safety_notes=raw.get("safety_notes", ""),
        source=source,
    )


def analyze(text: str, protocol_hint: str | None = None, adapter: LLMAdapter | None = None) -> ThreatAnalysis:
    """Analyze free text; use LLM if configured, otherwise rule-based."""
    settings = get_settings()
    adapter = adapter or get_adapter(settings)
    if not adapter.is_configured:
        logger.info("LLM nao configurado; usando analise baseada em regras.")
        return rules_analyze(text, protocol_hint)

    try:
        response = adapter.chat(
            ANALYSIS_SYSTEM_PROMPT,
            analysis_user_prompt(text, protocol_hint),
        )
        raw = adapter.extract_json(response.text)
        if raw is None:
            raise ValueError("LLM response did not contain valid JSON")
        analysis = _coerce_analysis(raw, source=settings.llm_provider, model=response.model, seed=response.seed)
        logger.info("Analise LLM bem-sucedida via %s", settings.llm_provider)
        return analysis
    except Exception as exc:  # noqa: BLE001
        logger.warning("Falha no LLM (%s); fallback para regras: %s", settings.llm_provider, exc)
        return rules_analyze(text, protocol_hint)


def analyze_vuln(
    vuln: Vulnerability,
    protocol: str | None = None,
    adapter: LLMAdapter | None = None,
) -> ThreatAnalysis:
    """Analyze a stored vulnerability record."""
    return analyze(vuln_to_text(vuln), protocol_hint=protocol, adapter=adapter)
