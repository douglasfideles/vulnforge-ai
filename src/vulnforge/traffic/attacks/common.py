"""Common utilities for native traffic attacks."""

from __future__ import annotations

import argparse
import random
import socket
import time
from typing import Callable

from ..safety import UnsafeTargetError, validate_target


DEFAULT_RATE = 10
DEFAULT_DURATION = 30
DEFAULT_PORT = 8888


def synth_parser() -> argparse.ArgumentParser:
    """Return a base argument parser for native attack modules."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--transport", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE)
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--benign", action="store_true")
    return parser


def send_loop(
    transport: str,
    target: str,
    port: int,
    duration: int,
    rate: int,
    payload_factory: Callable[[int], bytes],
) -> int:
    """Send payloads to target with a fixed rate and duration."""
    sent = 0
    interval = 1.0 / rate if rate > 0 else 0.0
    end = time.monotonic() + duration
    seq = 0
    if transport == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            while time.monotonic() < end:
                payload = payload_factory(seq)
                sock.sendto(payload, (target, port))
                sent += 1
                seq += 1
                if interval:
                    time.sleep(interval)
    else:
        with socket.create_connection((target, port), timeout=5.0) as sock:
            while time.monotonic() < end:
                payload = payload_factory(seq)
                sock.sendall(payload)
                sent += 1
                seq += 1
                if interval:
                    time.sleep(interval)
    return sent


def run_and_report(
    make_parser: Callable[[], argparse.ArgumentParser],
    mutator: Callable[[bytes, int, random.Random], bytes],
    baseline: bytes = b"",
) -> None:
    """Common main for native attacks: parse args, validate target, run loop, print summary."""
    parser = make_parser()
    args = parser.parse_args()
    try:
        validate_target(args.target)
    except UnsafeTargetError as exc:
        parser.error(str(exc))
    rng = random.Random(args.seed)

    def factory(seq: int) -> bytes:
        if args.benign:
            return baseline
        return mutator(baseline, seq, rng)

    sent = send_loop(args.transport, args.target, args.port, args.duration, args.rate, factory)
    print(f"Sent {sent} packets to {args.target}:{args.port} ({args.transport})")


if __name__ == "__main__":
    def _identity(baseline: bytes, seq: int, rng: random.Random) -> bytes:
        return baseline
    run_and_report(synth_parser, _identity, baseline=b"PING")
