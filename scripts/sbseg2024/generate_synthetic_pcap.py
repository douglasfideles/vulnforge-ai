#!/usr/bin/env python
"""Gera PCAPs sinteticos do testbed SBSeg 2024 usando Scapy (sem root).

Simula multiplas sessoes de 3 sensores IoT, cada sessao com porta diferente,
gerando centenas de fluxos bidirecionais — comparavel ao dataset real SBSeg.

Cenario Normal: sessoes curtas de ~5s a 1 pkt/s (sensor envia heartbeat periodico)
Cenario DoS:    sessoes curtas de ~2s a 50 pkt/s (sensor inunda agente sem controle)

Uso:
    python scripts/sbseg2024/generate_synthetic_pcap.py
    python scripts/sbseg2024/generate_synthetic_pcap.py --sessions 300
"""
from __future__ import annotations

import argparse
import random
import struct
import time
from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

REPO = Path(__file__).resolve().parent.parent.parent
RUNS_DIR = REPO / "data" / "sbseg2024" / "runs"

AGENT_IP = "127.0.0.1"
AGENT_PORT = 7400
SENSOR_IPS = ["127.0.0.2", "127.0.0.3", "127.0.0.4"]

# Cabecalho minimo RTPS/DDS (magic + version + vendor)
_RTPS_HDR = b"RTPS\x02\x04\x01\x0f" + b"\x00" * 12  # 20 bytes


def _sensor_payload(sensor_id: int, seq: int, size: int = 40) -> bytes:
    rng = random.Random(sensor_id * 31337 + seq)
    data = struct.pack(">HHH", sensor_id, seq % 65536, rng.randint(0, 1000))
    data += bytes(rng.getrandbits(8) for _ in range(size - 6))
    return _RTPS_HDR + data


def _agent_reply(seq: int) -> bytes:
    return _RTPS_HDR + b"\x00\x01" + struct.pack(">H", seq % 65536) + b"\x00" * 4


def _make_session(
    sensor_ip: str,
    src_port: int,
    session_start: float,
    rate_pps: float,
    duration: float,
    sensor_id: int,
    seq_offset: int,
) -> list:
    """Gera pacotes de uma sessao (1 fluxo cicflowmeter por sessao)."""
    packets = []
    interval = 1.0 / rate_pps
    t = 0.0
    seq = seq_offset
    while t < duration:
        pkt_time = session_start + t

        # sensor → agente
        fwd_payload = _sensor_payload(sensor_id, seq, size=40)
        fwd = IP(src=sensor_ip, dst=AGENT_IP, ttl=64) / UDP(
            sport=src_port, dport=AGENT_PORT
        ) / Raw(load=fwd_payload)
        fwd.time = pkt_time
        packets.append(fwd)

        # agente → sensor (reply ~1ms)
        bwd_payload = _agent_reply(seq)
        bwd = IP(src=AGENT_IP, dst=sensor_ip, ttl=64) / UDP(
            sport=AGENT_PORT, dport=src_port
        ) / Raw(load=bwd_payload)
        bwd.time = pkt_time + 0.001
        packets.append(bwd)

        t += interval
        seq += 1

    return packets


def generate_pcap(
    out_path: Path,
    n_sessions: int,
    rate_pps: float,
    session_duration: float,
    session_gap: float,
    seed: int = 42,
) -> tuple[int, int]:
    """Gera PCAP com multiplas sessoes.

    Returns: (num_packets, num_sessions_total)
    """
    rng = random.Random(seed)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    packets = []
    base_time = 1_700_000_000.0
    n_sensors = len(SENSOR_IPS)
    sessions_per_sensor = n_sessions // n_sensors

    for sensor_idx, sensor_ip in enumerate(SENSOR_IPS):
        t = base_time + sensor_idx * 0.1  # leve offset entre sensores
        seq_offset = sensor_idx * 100000

        for s in range(sessions_per_sensor):
            src_port = 40000 + sensor_idx * 10000 + s
            dur = session_duration + rng.uniform(-0.5, 0.5) * session_duration * 0.1
            pkts = _make_session(
                sensor_ip=sensor_ip,
                src_port=src_port,
                session_start=t,
                rate_pps=rate_pps,
                duration=dur,
                sensor_id=sensor_idx,
                seq_offset=seq_offset + s * 1000,
            )
            packets.extend(pkts)
            t += dur + session_gap + rng.uniform(0, session_gap * 0.2)

    packets.sort(key=lambda p: float(p.time))
    wrpcap(str(out_path), packets)
    return len(packets), n_sessions


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera PCAPs sinteticos SBSeg 2024")
    parser.add_argument("--sessions", type=int, default=400,
                        help="Total de sessoes (dividido entre 3 sensores, default: 400)")
    args = parser.parse_args()

    print(f"Gerando PCAPs ({args.sessions} sessoes, 3 sensores)...")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    # Normal: 1 pkt/s, sessoes de 5s, gap 1s → cicflowmeter cria 1 fluxo por sessao
    normal_path = RUNS_DIR / "xrce_dds_normal.pcap"
    n_pkts, n_sess = generate_pcap(
        out_path=normal_path,
        n_sessions=args.sessions,
        rate_pps=1.0,
        session_duration=5.0,
        session_gap=1.0,
        seed=1,
    )
    size_kb = normal_path.stat().st_size // 1024
    print(f"  Normal: {normal_path}")
    print(f"    {n_pkts} pacotes, ~{n_sess} sessoes, {size_kb} KB")

    # DoS: 50 pkt/s, sessoes de 2s, gap 0.5s → alta taxa por sessao
    dos_path = RUNS_DIR / "xrce_dds_dos.pcap"
    n_pkts, n_sess = generate_pcap(
        out_path=dos_path,
        n_sessions=args.sessions,
        rate_pps=50.0,
        session_duration=2.0,
        session_gap=0.5,
        seed=2,
    )
    size_kb = dos_path.stat().st_size // 1024
    print(f"  DoS:    {dos_path}")
    print(f"    {n_pkts} pacotes, ~{n_sess} sessoes, {size_kb} KB")


if __name__ == "__main__":
    main()
