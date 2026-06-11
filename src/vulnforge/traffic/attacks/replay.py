"""Replay de mensagens capturadas: reenvia payloads de um PCAP contra o alvo."""

from __future__ import annotations

import time

from ..safety import assert_safe
from .common import base_parser, open_socket, run_and_report


def _extract_payloads(pcap_path: str, port: int) -> list[bytes]:
    """Extrai payloads de transporte do PCAP (requer scapy). Filtra pela porta alvo."""
    try:
        from scapy.all import TCP, UDP, rdpcap  # type: ignore
    except ImportError as exc:  # degrade gracioso
        raise RuntimeError(
            "scapy nao instalado: necessario para ler PCAP no replay. "
            "Instale com `pip install scapy` (extra 'traffic')."
        ) from exc

    packets = rdpcap(pcap_path)
    payloads: list[bytes] = []
    for pkt in packets:
        layer = pkt.getlayer(UDP) or pkt.getlayer(TCP)
        if layer is None:
            continue
        raw = bytes(layer.payload)
        if raw:
            payloads.append(raw)
    return payloads


def main(argv: list[str] | None = None) -> int:
    parser = base_parser("Replay de mensagens capturadas (PCAP) contra alvo de laboratorio.")
    parser.add_argument("--pcap", required=True, help="Arquivo PCAP de origem")
    parser.add_argument("--loops", type=int, default=0, help="Repeticoes (0 = ate --duration)")
    args = parser.parse_args(argv)

    assert_safe(args.target)
    payloads = _extract_payloads(args.pcap, args.port)
    if not payloads:
        print(f"[replay] nenhum payload encontrado em {args.pcap}")
        return 1

    interval = 1.0 / args.rate if args.rate > 0 else 0.0
    sock = open_socket(args.transport, args.target, args.port)
    sent = 0
    deadline = time.monotonic() + args.duration
    try:
        loop = 0
        while True:
            for raw in payloads:
                try:
                    sock.send(raw)
                    sent += 1
                except OSError:
                    if args.transport == "tcp":
                        raise
                if interval:
                    time.sleep(interval)
                if args.loops == 0 and time.monotonic() >= deadline:
                    break
            loop += 1
            if args.loops and loop >= args.loops:
                break
            if args.loops == 0 and time.monotonic() >= deadline:
                break
    finally:
        sock.close()

    run_and_report("replay", sent, args.target, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
