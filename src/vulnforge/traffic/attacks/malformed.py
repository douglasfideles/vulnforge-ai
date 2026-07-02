"""Native malformed message attack."""

from __future__ import annotations

import random
import struct

from .common import run_and_report, synth_parser


def malformed_mutator(baseline: bytes, seq: int, rng: random.Random) -> bytes:
    if not baseline:
        return rng.randbytes(16)
    buf = bytearray(baseline)
    if buf:
        buf[0] ^= 0xFF
    if len(buf) > 1:
        buf[1] = rng.randrange(256)
    buf.extend(rng.randbytes(8))
    return bytes(buf) + struct.pack("<I", seq & 0xFFFFFFFF)


def main() -> None:
    baseline = b"MALFORMED" + struct.pack("<I", 0)
    run_and_report(synth_parser, malformed_mutator, baseline=baseline)


if __name__ == "__main__":
    main()
