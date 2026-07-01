#!/usr/bin/env python
"""Gera PCAPs sinteticos do testbed SBSeg 2024 — v2, fiel ao firmware ESP8266.

Diferenca para a v1 (generate_synthetic_pcap.py): em vez de payload fixo de 40 bytes
aleatorios, este gerador reproduz o comportamento do firmware real usado para capturar
o dataset SBSeg 2024 (projeto DDS-ESP8266, lib Micro-XRCE-DDS):

  * Topico ``helloworld { uint32 index; char message[255]; }`` (helloworld.h)
  * O firmware envia uma mensagem cujo tamanho CRESCE de 10 -> 255 caracteres e faz
    wrap de volta a 10 (main.cpp: message_size++, com INITIAL=10 / MAX=255).
  * Stream confiavel: o agente responde com ACK/replicas (trafego backward grande).

Calibracao empirica (dataset real rede-isolada, por fluxo):
  ~8 pacotes forward + ~1 backward por fluxo; Fwd Pkt Len Mean ~336 B (mediana 386),
  Pkt Len Std ~78; Bwd Pkt Len Mean ~350; Fwd IAT ~0.21 s (normal) / ~0.10 s (DoS).

Como o cicflowmeter mede o comprimento do pacote IP (= 28 B de cabecalho IP+UDP +
payload), o comprimento alvo de cada pacote forward e ``BASE_LEN + message_size``,
onde ``message_size`` e amostrado da rampa uniforme 10..255 do firmware. BASE_LEN e
calibrado para que a media (BASE + 132.5) caia em ~336 B, e o desvio dentro do fluxo
vem naturalmente da rampa (std uniforme 10..255 ~ 70.7), proximo ao real (~78).

Uso:
    python scripts/sbseg2024/generate_synthetic_pcap_v2.py
    python scripts/sbseg2024/generate_synthetic_pcap_v2.py --sessions 15000   # escala ~real
    python scripts/sbseg2024/generate_synthetic_pcap_v2.py --base-len 204
"""
from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

REPO = Path(__file__).resolve().parent.parent.parent
RUNS_DIR = REPO / "data" / "sbseg2024" / "runs_v2"

AGENT_IP = "127.0.0.1"
AGENT_PORT = 7400
SENSOR_IPS = ["127.0.0.2", "127.0.0.3", "127.0.0.4"]

# Firmware DDS-ESP8266: tamanho do campo message cresce 10 -> 255 e faz wrap.
MSG_MIN = 10
MSG_MAX = 255

# Comprimento IP-base de um pacote de dados (sem o campo message): cabecalho IP+UDP (28)
# + framing Micro-XRCE-DDS/RTPS (session header + submessage WRITE_DATA + serializacao do
# topico). Calibrado para que BASE_LEN + media(message_size 10..255 = 132.5) ~ 336 B (real).
DEFAULT_BASE_LEN = 204

# Cabecalho minimo RTPS/DDS (magic + version + vendor) — apenas cosmetico no payload.
_RTPS_HDR = b"RTPS\x02\x04\x01\x0f" + b"\x00" * 12  # 20 bytes


def _alphabet_message(size: int) -> bytes:
    """Reproduz o preenchimento do firmware: message[i] = 'A' + (i % 26)."""
    return bytes((ord("A") + (i % 26)) for i in range(size))


def _data_payload(sensor_id: int, index: int, message_size: int, base_len: int) -> bytes:
    """Monta o payload de um pacote de dados com comprimento IP alvo = base_len + message_size.

    Estrutura: RTPS hdr | uint32 index | uint32 strlen | message (alfabeto) | padding RTPS.
    O comprimento total e ajustado para que IP+UDP (28) + payload == base_len + message_size.
    """
    target_ip_len = base_len + message_size
    target_payload = max(target_ip_len - 28, len(_RTPS_HDR) + 8)
    body = _RTPS_HDR + struct.pack(">II", index & 0xFFFFFFFF, message_size)
    body += _alphabet_message(message_size)
    if len(body) < target_payload:
        body += b"\x00" * (target_payload - len(body))
    else:
        body = body[:target_payload]
    return body


def _agent_reply(index: int, reply_size: int) -> bytes:
    """Resposta do agente XRCE-DDS (ACK do stream confiavel) — pacote backward grande."""
    target_payload = max(reply_size - 28, len(_RTPS_HDR) + 8)
    body = _RTPS_HDR + b"\x00\x01" + struct.pack(">I", index & 0xFFFFFFFF)
    if len(body) < target_payload:
        body += b"\x00" * (target_payload - len(body))
    return body[:target_payload]


def _make_session(
    sensor_ip: str,
    src_port: int,
    session_start: float,
    iat: float,
    n_fwd: int,
    sensor_id: int,
    index_offset: int,
    base_len: int,
    rng: random.Random,
) -> list:
    """Gera um fluxo (cicflowmeter trata cada sessao/5-tupla como um fluxo)."""
    packets = []
    t = 0.0
    # Um ACK grande do agente, perto do inicio do fluxo (tot_bwd ~ 1, como no real).
    ack_after = rng.randint(1, max(1, n_fwd - 1))

    # Cada fluxo captura uma FASE diferente da rampa 10->255 do firmware: alguns fluxos
    # pegam mensagens grandes (perto do wrap), outros pequenas. Isso reproduz a alta
    # variancia ENTRE fluxos do dataset real (Fwd Pkt Len Mean mediana 386, cauda longa).
    hi = rng.randint(120, MSG_MAX)
    lo = rng.randint(MSG_MIN, hi)

    for k in range(n_fwd):
        index = index_offset + k
        # Tamanho da mensagem amostrado da janela de rampa deste fluxo.
        message_size = rng.randint(lo, hi)
        pkt_time = session_start + t

        fwd_payload = _data_payload(sensor_id, index, message_size, base_len)
        fwd = IP(src=sensor_ip, dst=AGENT_IP, ttl=64) / UDP(
            sport=src_port, dport=AGENT_PORT
        ) / Raw(load=fwd_payload)
        fwd.time = pkt_time
        packets.append(fwd)

        if k == ack_after:
            reply_size = rng.randint(386, 460)  # backward grande (~420 no real)
            bwd_payload = _agent_reply(index, reply_size)
            bwd = IP(src=AGENT_IP, dst=sensor_ip, ttl=64) / UDP(
                sport=AGENT_PORT, dport=src_port
            ) / Raw(load=bwd_payload)
            bwd.time = pkt_time + 0.001
            packets.append(bwd)

        t += iat * (1.0 + rng.uniform(-0.2, 0.2))  # jitter no IAT

    return packets


def generate_pcap(
    out_path: Path,
    n_sessions: int,
    iat: float,
    base_len: int,
    seed: int = 42,
) -> tuple[int, int]:
    """Gera PCAP com multiplas sessoes (1 fluxo por sessao)."""
    rng = random.Random(seed)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    packets: list = []
    base_time = 1_700_000_000.0
    n_sensors = len(SENSOR_IPS)
    sessions_per_sensor = n_sessions // n_sensors

    for sensor_idx, sensor_ip in enumerate(SENSOR_IPS):
        t = base_time + sensor_idx * 0.1
        index = sensor_idx * 1_000_000

        for s in range(sessions_per_sensor):
            src_port = 40000 + sensor_idx * 10000 + s
            n_fwd = rng.randint(5, 12)  # mediana ~8, como no real
            pkts = _make_session(
                sensor_ip=sensor_ip,
                src_port=src_port,
                session_start=t,
                iat=iat,
                n_fwd=n_fwd,
                sensor_id=sensor_idx,
                index_offset=index,
                base_len=base_len,
                rng=rng,
            )
            packets.extend(pkts)
            index += n_fwd
            session_span = n_fwd * iat
            t += session_span + rng.uniform(1.0, 3.0)  # gap entre sessoes

    packets.sort(key=lambda p: float(p.time))
    wrpcap(str(out_path), packets)
    return len(packets), sessions_per_sensor * n_sensors


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera PCAPs sinteticos SBSeg 2024 (v2, fiel ao ESP8266)")
    parser.add_argument("--sessions", type=int, default=400,
                        help="Total de sessoes/fluxos por cenario (dividido entre 3 sensores)")
    parser.add_argument("--base-len", type=int, default=DEFAULT_BASE_LEN,
                        help="Comprimento IP-base do pacote de dados (calibra Fwd Pkt Len Mean)")
    args = parser.parse_args()

    print(f"Gerando PCAPs v2 ({args.sessions} sessoes, 3 sensores, base_len={args.base_len})...")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    # Normal: IAT ~0.21 s (real rede-isolada). Fluxos curtos, taxa moderada.
    normal_path = RUNS_DIR / "xrce_dds_normal.pcap"
    n_pkts, n_sess = generate_pcap(normal_path, args.sessions, iat=0.21,
                                   base_len=args.base_len, seed=1)
    print(f"  Normal: {normal_path}  ({n_pkts} pacotes, {n_sess} sessoes, "
          f"{normal_path.stat().st_size // 1024} KB)")

    # DoS: IAT ~0.10 s (real) — alta taxa por fluxo.
    dos_path = RUNS_DIR / "xrce_dds_dos.pcap"
    n_pkts, n_sess = generate_pcap(dos_path, args.sessions, iat=0.10,
                                   base_len=args.base_len, seed=2)
    print(f"  DoS:    {dos_path}  ({n_pkts} pacotes, {n_sess} sessoes, "
          f"{dos_path.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
