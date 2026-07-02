"""Native oversized payload attack."""

from __future__ import annotations

import random
import struct

from .common import run_and_report, synth_parser


def oversized_mutator(baseline: bytes, seq: int, rng: random.Random) -> bytes:
    padding = b"\xff" * 60000
    return baseline + padding + struct.pack("<I", seq & 0xFFFFFFFF)


def main() -> None:
    baseline = b"OVERSIZED" + struct.pack("<I", 0)
    run_and_report(synth_parser, oversized_mutator, baseline=baseline)


if __name__ == "__main__":
    main()
