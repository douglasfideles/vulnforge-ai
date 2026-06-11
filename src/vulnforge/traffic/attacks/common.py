"""Utilitarios compartilhados pelos ataques nativos."""

from __future__ import annotations

import argparse
import socket
import time
from collections.abc import Callable

from ..safety import assert_safe


def base_parser(description: str) -> argparse.ArgumentParser:
    """Parser com os argumentos comuns a todos os ataques."""
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--target", required=True, help="IP/host alvo (deve ser privado/loopback)")
    p.add_argument("--port", type=int, required=True, help="Porta alvo")
    p.add_argument("--transport", choices=["udp", "tcp"], default="udp")
    p.add_argument("--duration", type=float, default=15.0, help="Duracao em segundos")
    p.add_argument("--rate", type=float, default=50.0, help="Pacotes por segundo (limite)")
    return p


def synth_parser(
    description: str, port: int, transport: str, duration: float, rate: float
) -> argparse.ArgumentParser:
    """Parser para ataques SINTETIZADOS: --port/--transport ja vem do CVE (overridable)."""
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--target", required=True, help="IP/host alvo (deve ser privado/loopback)")
    p.add_argument("--port", type=int, default=port, help="Porta alvo")
    p.add_argument("--transport", choices=["udp", "tcp"], default=transport)
    p.add_argument("--duration", type=float, default=duration, help="Duracao em segundos")
    p.add_argument("--rate", type=float, default=rate, help="Pacotes por segundo (limite)")
    return p


def open_socket(transport: str, target: str, port: int) -> socket.socket:
    """Abre socket UDP (connectionless) ou TCP (conectado)."""
    if transport == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((target, port))
        return sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((target, port))
    return sock


def send_loop(
    transport: str,
    target: str,
    port: int,
    duration: float,
    rate: float,
    payload_factory: Callable[[int], bytes],
) -> int:
    """Envia pacotes ate `duration` respeitando `rate` (pkt/s). Retorna total enviado.

    Aplica a guarda de seguranca antes de qualquer envio.
    """
    assert_safe(target)
    interval = 1.0 / rate if rate > 0 else 0.0
    sent = 0
    deadline = time.monotonic() + duration
    sock = open_socket(transport, target, port)
    try:
        while time.monotonic() < deadline:
            payload = payload_factory(sent)
            try:
                sock.send(payload)
                sent += 1
            except OSError:
                # Alvo pode recusar/encerrar; em UDP reabre, em TCP encerra.
                if transport == "tcp":
                    break
            if interval:
                time.sleep(interval)
    finally:
        sock.close()
    return sent


def run_and_report(name: str, sent: int, target: str, port: int) -> None:
    print(f"[{name}] enviados {sent} pacotes para {target}:{port}")
