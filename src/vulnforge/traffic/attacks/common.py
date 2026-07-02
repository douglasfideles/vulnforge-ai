from __future__ import annotations

import argparse
import socket
import time
from collections.abc import Callable

from vulnforge.traffic.safety import resolve_safe_target


def synth_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--transport", choices=("udp", "tcp"), default="udp")
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--rate", type=float, default=20)
    return parser


def send_loop(transport: str, target: str, port: int, duration: float, rate: float, factory: Callable[[int], bytes]) -> int:
    address = resolve_safe_target(target)
    sock_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    sent = 0
    with socket.socket(socket.AF_INET, sock_type) as sock:
        if transport == "tcp":
            sock.settimeout(2)
            sock.connect((address, port))
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            payload = factory(sent)[:65507]
            if transport == "udp":
                sock.sendto(payload, (address, port))
            else:
                sock.sendall(payload)
            sent += 1
            time.sleep(1 / max(rate, 0.1))
    return sent


def run_and_report(args, factory) -> None:
    count = send_loop(args.transport, args.target, args.port, args.duration, args.rate, factory)
    print(f"sent={count} target={args.target}:{args.port} transport={args.transport}")

