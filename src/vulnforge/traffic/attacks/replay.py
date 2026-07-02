"""Replay attack: resend packets captured from a reference PCAP."""

from __future__ import annotations

import argparse
import random
import struct

from .common import run_and_report


def replay_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--transport", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--rate", type=int, default=10)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--pcap", default="")
    return parser


def replay_mutator(baseline: bytes, seq: int, rng: random.Random) -> bytes:
    return baseline + struct.pack("<I", seq & 0xFFFFFFFF)


def main() -> None:
    parser = replay_parser()
    args = parser.parse_args()
    baseline = b"REPLAY"
    if args.pcap:
        try:
            from scapy.all import rdpcap  # type: ignore[import-not-found]
            pkts = rdpcap(args.pcap)
            if pkts:
                baseline = bytes(pkts[0].payload)
        except Exception:
            pass
    run_and_report(lambda: parser, replay_mutator, baseline=baseline)


if __name__ == "__main__":
    main()
