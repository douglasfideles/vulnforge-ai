"""PCAP analysis for effect validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging_setup import get_logger

logger = get_logger(__name__)


class PcapStats(dict):
    """Dictionary-like PCAP statistics container."""

    def __init__(self, **kwargs: Any) -> None:
        defaults = {
            "total_packets": 0,
            "packets_out": 0,
            "packets_in": 0,
            "tcp_rst": 0,
            "icmp_unreachable": 0,
            "target_ip": "",
            "note": "",
        }
        defaults.update(kwargs)
        super().__init__(defaults)


def analyze_pcap(pcap_path: str | Path, target_ip: str = "") -> PcapStats:
    """Count packets, RSTs, ICMP unreachable; return empty stats if scapy missing."""
    try:
        from scapy.all import ICMP, IP, TCP, rdpcap  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("scapy nao disponivel; analise PCAP indisponivel.")
        return PcapStats(note="scapy nao instalado")

    path = Path(pcap_path)
    if not path.exists():
        return PcapStats(note=f"PCAP nao encontrado: {path}")

    try:
        pkts = rdpcap(str(path))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Falha ao ler PCAP: %s", exc)
        return PcapStats(note=f"falha ao ler PCAP: {exc}")

    total = len(pkts)
    packets_out = 0
    packets_in = 0
    tcp_rst = 0
    icmp_unreachable = 0

    for pkt in pkts:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        if target_ip:
            if ip.src == target_ip:
                packets_in += 1
            if ip.dst == target_ip:
                packets_out += 1
        if pkt.haslayer(TCP) and pkt[TCP].flags & 0x04:
            tcp_rst += 1
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 3:
            icmp_unreachable += 1

    return PcapStats(
        total_packets=total,
        packets_out=packets_out,
        packets_in=packets_in,
        tcp_rst=tcp_rst,
        icmp_unreachable=icmp_unreachable,
        target_ip=target_ip,
        note="analise concluida",
    )
