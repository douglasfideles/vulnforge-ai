"""Harness de validacao de efeito: sonda antes/depois + analise de PCAP -> veredito."""

from __future__ import annotations

from ..logging_setup import get_logger
from ..models import EffectReport, ProbeResult
from ..protocols.base import ProtocolPlugin
from .pcap_analysis import PcapStats, analyze_pcap

log = get_logger(__name__)


def probe(plugin: ProtocolPlugin, target: str, port: int | None = None) -> ProbeResult:
    """Sonda de saude do alvo via plugin do protocolo (tolerante a erros)."""
    try:
        return plugin.health_probe(target, port)
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(responsive=False, source="probe", detail=f"Sonda falhou: {exc}")


def decide_verdict(
    before: ProbeResult | None, after: ProbeResult | None, stats: PcapStats
) -> str:
    """Regra de veredito: valid | invalid | inconclusive.

    - respondia antes e parou de responder  => valid (efeito de disponibilidade)
    - anomalias no PCAP (RST/ICMP/sem resposta) => valid
    - respondia antes e continua respondendo, sem anomalias => invalid
    - demais casos => inconclusive
    """
    b = before.responsive if before else None
    a = after.responsive if after else None

    if b is True and a is False:
        return "valid"
    if stats.anomalies:
        return "valid"
    if b is True and a is True:
        return "invalid"
    return "inconclusive"


def build_report(
    before: ProbeResult | None, after: ProbeResult | None,
    pcap_path: str | None, target: str | None,
    packets_out: int = 0,
) -> EffectReport:
    """Monta o EffectReport combinando sondas + analise de PCAP."""
    stats = analyze_pcap(pcap_path, target) if pcap_path else PcapStats(note="sem pcap")
    verdict = decide_verdict(before, after, stats)
    notes = []
    if before:
        notes.append(f"antes: {before.detail}")
    if after:
        notes.append(f"depois: {after.detail}")
    if stats.note:
        notes.append(stats.note)
    return EffectReport(
        verdict=verdict,
        responsive_before=(before.responsive if before else None),
        responsive_after=(after.responsive if after else None),
        packets_out=packets_out,
        packets_in=stats.packets_from_target,
        anomalies=list(stats.anomalies),
        notes=" | ".join(notes),
    )
