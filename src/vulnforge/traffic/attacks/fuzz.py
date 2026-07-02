"""Native fuzz attack with multiple strategies."""

from __future__ import annotations

import random
import struct

from .common import run_and_report, synth_parser


def fuzz_mutator(baseline: bytes, seq: int, rng: random.Random) -> bytes:
    if not baseline:
        return rng.randbytes(16)
    buf = bytearray(baseline)
    # Strategy chosen by sequence number.
    strategy = seq % 4
    if strategy == 0 and buf:
        buf[rng.randrange(len(buf))] = rng.randrange(256)
    elif strategy == 1:
        buf.extend(rng.randbytes(rng.randrange(1, 64)))
    elif strategy == 2 and buf:
        start = rng.randrange(len(buf))
        length = rng.randrange(1, min(8, len(buf) - start + 1))
        for i in range(start, start + length):
            buf[i] = 0xFF
    else:
        buf = bytearray(rng.randbytes(max(len(buf), 8)))
    return bytes(buf)


def main() -> None:
    baseline = b"FUZZ" + struct.pack("<I", 0)
    run_and_report(synth_parser, fuzz_mutator, baseline=baseline)


if __name__ == "__main__":
    main()
