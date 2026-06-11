"""Analise pos-execucao do PCAP para detectar anomalias indicativas de efeito.

Procura sinais de que o alvo reagiu/sofreu: RST TCP, ICMP unreachable, ausencia de
respostas. Requer scapy (extra `traffic`); sem ele, retorna resultado vazio com nota.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class PcapStats:
    packets_total: int = 0
    packets_to_target: int = 0
    packets_from_target: int = 0
    tcp_rst: int = 0
    icmp_unreachable: int = 0
    anomalies: list[str] = field(default_factory=list)
    note: str = ""


def analyze_pcap(pcap_path: str | Path, target: str | None = None) -> PcapStats:
    """Conta pacotes e anomalias no PCAP. Degrada com nota se scapy/arquivo ausente."""
    stats = PcapStats()
    path = Path(pcap_path)
    if not path.exists():
        stats.note = f"PCAP nao encontrado: {path}"
        return stats

    try:
        from scapy.all import ICMP, IP, TCP, rdpcap  # type: ignore
    except ImportError:
        stats.note = "scapy ausente: analise de PCAP indisponivel (pip install scapy)."
        return stats

    packets = rdpcap(str(path))
    stats.packets_total = len(packets)
    for pkt in packets:
        ip = pkt.getlayer(IP)
        if ip is not None and target:
            if ip.dst == target:
                stats.packets_to_target += 1
            if ip.src == target:
                stats.packets_from_target += 1
        tcp = pkt.getlayer(TCP)
        if tcp is not None and tcp.flags & 0x04:  # RST
            stats.tcp_rst += 1
        icmp = pkt.getlayer(ICMP)
        if icmp is not None and int(icmp.type) == 3:  # destination unreachable
            stats.icmp_unreachable += 1

    if stats.tcp_rst:
        stats.anomalies.append(f"{stats.tcp_rst} TCP RST (conexoes recusadas/encerradas)")
    if stats.icmp_unreachable:
        stats.anomalies.append(f"{stats.icmp_unreachable} ICMP unreachable")
    if target and stats.packets_to_target and stats.packets_from_target == 0:
        stats.anomalies.append("alvo nao respondeu a nenhum pacote (possivel queda/saturacao)")
    return stats
