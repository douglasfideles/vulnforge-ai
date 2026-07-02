"""Effect validation harness: probe before/after + PCAP verdict."""

from __future__ import annotations

from pathlib import Path

from ..logging_setup import get_logger
from ..models import EffectReport, ProbeResult
from ..protocols.base import ProtocolPlugin
from ..traffic.safety import UnsafeTargetError, validate_target
from .pcap_analysis import PcapStats, analyze_pcap

logger = get_logger(__name__)


def _extract_target_ip(target: str) -> str:
    try:
        return validate_target(target)
    except UnsafeTargetError:
        return target


def probe_target(plugin: ProtocolPlugin | None, target: str, port: int | None = None) -> ProbeResult:
    if plugin is None:
        return ProbeResult(responsive=False, detail="Plugin nao disponivel", source="probe")
    try:
        return plugin.health_probe(target, port)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Probe falhou: %s", exc)
        return ProbeResult(responsive=False, detail=f"excecao: {exc}", source="probe")


def decide_verdict(
    before: ProbeResult,
    after: ProbeResult,
    stats: PcapStats,
) -> EffectReport:
    """Apply the verdict rules from RF-44."""
    anomalies: list[str] = []
    if stats.get("tcp_rst", 0) > 0:
        anomalies.append("TCP RST observado")
    if stats.get("icmp_unreachable", 0) > 0:
        anomalies.append("ICMP destination-unreachable observado")
    if stats.get("packets_out", 0) > 0 and stats.get("packets_in", 0) == 0:
        anomalies.append("alvo recebeu pacotes mas nao respondeu")

    if before.responsive and not after.responsive:
        verdict = "valid"
    elif anomalies:
        verdict = "valid"
    elif before.responsive and after.responsive:
        verdict = "invalid"
    else:
        verdict = "inconclusive"

    return EffectReport(
        verdict=verdict,
        responsive_before=before.responsive,
        responsive_after=after.responsive,
        packets_out=stats.get("packets_out", 0),
        packets_in=stats.get("packets_in", 0),
        anomalies=anomalies,
        notes=stats.get("note", ""),
    )


def run_validation(
    plugin: ProtocolPlugin | None,
    target: str,
    pcap_path: str | Path,
    port: int | None = None,
) -> EffectReport:
    """Probe before, analyze PCAP, probe after, decide verdict."""
    before = probe_target(plugin, target, port)
    target_ip = _extract_target_ip(target)
    stats = analyze_pcap(pcap_path, target_ip=target_ip)
    after = probe_target(plugin, target, port)
    return decide_verdict(before, after, stats)
