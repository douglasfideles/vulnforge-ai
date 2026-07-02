from pathlib import Path


def analyze_pcap(path: str | Path, target: str) -> dict:
    empty = {"total_packets": 0, "packets_out": 0, "packets_in": 0, "tcp_rst": 0, "icmp_unreachable": 0, "anomalies": []}
    if not Path(path).exists():
        return {**empty, "note": "PCAP is missing; packet analysis skipped"}
    try:
        from scapy.all import ICMP, IP, TCP, rdpcap
    except Exception as exc:
        return {
            **empty,
            "note": (
                "Scapy unavailable in this environment; install vulnforge-ai[traffic] "
                f"and allow packet-interface discovery for PCAP analysis ({type(exc).__name__}: {exc})"
            ),
        }
    packets = rdpcap(str(path))
    stats = {**empty, "total_packets": len(packets)}
    for packet in packets:
        if IP in packet:
            if packet[IP].dst == target:
                stats["packets_out"] += 1
            if packet[IP].src == target:
                stats["packets_in"] += 1
        if TCP in packet and int(packet[TCP].flags) & 0x04:
            stats["tcp_rst"] += 1
        if ICMP in packet and int(packet[ICMP].type) == 3:
            stats["icmp_unreachable"] += 1
    if stats["tcp_rst"]:
        stats["anomalies"].append(f"{stats['tcp_rst']} TCP reset packet(s)")
    if stats["icmp_unreachable"]:
        stats["anomalies"].append(f"{stats['icmp_unreachable']} ICMP destination-unreachable packet(s)")
    if stats["packets_out"] and not stats["packets_in"]:
        stats["anomalies"].append("target sent no response while receiving packets")
    return stats
