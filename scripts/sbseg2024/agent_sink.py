#!/usr/bin/env python
"""Simula o agente XRCE-DDS: recebe pacotes UDP em 7400 e responde (loopback).

O agente gera trafego backward para que o cicflowmeter produza fluxos bidirecionais,
como nos dispositivos reais do testbed SBSeg 2024 (agente XRCE-DDS no notebook/RPi).

Uso:
    python scripts/sbseg2024/agent_sink.py
    python scripts/sbseg2024/agent_sink.py --port 7400 --host 127.0.0.1
"""
import argparse
import signal
import socket
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Agente XRCE-DDS simulado (UDP sink + echo)")
    parser.add_argument("--port", type=int, default=7400)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.settimeout(1.0)

    def _stop(*_: object) -> None:
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    print(f"agent_sink: ouvindo UDP {args.host}:{args.port}", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            # resposta minima simulando STATUS_AGENT do protocolo XRCE-DDS
            sock.sendto(b"\x00\x01" + data[:2], addr)
        except socket.timeout:
            continue
        except OSError:
            break


if __name__ == "__main__":
    main()
