"""Native flooding attack with benign baseline mode."""

from __future__ import annotations

import random
import struct

from .common import run_and_report, synth_parser
from ...protocols.registry import get


def _baseline() -> bytes:
    try:
        plugin = get("XRCE-DDS")()
        return plugin.baseline_message(0)
    except Exception:
        return b"FLOOD" + struct.pack("<I", 0)


def flooding_mutator(baseline: bytes, seq: int, rng: random.Random) -> bytes:
    return baseline[:16] + struct.pack("<I", seq & 0xFFFFFFFF) + baseline[20:]


def main() -> None:
    baseline = _baseline()
    run_and_report(synth_parser, flooding_mutator, baseline=baseline)


if __name__ == "__main__":
    main()
