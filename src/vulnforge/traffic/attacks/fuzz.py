"""Fuzzer de protocolo com estrategias (random, valid_header, overflow, underflow)."""

from __future__ import annotations

import os
import random

from .common import base_parser, run_and_report, send_loop

STRATEGIES = ("random", "valid_header", "overflow", "underflow", "injection")


def _fuzz_payload(strategy: str, seq: int, rng: random.Random) -> bytes:
    if strategy == "valid_header":
        return bytes([0x80, 0x00, 0x00, 0x00]) + os.urandom(rng.randrange(8, 64))
    if strategy == "overflow":
        return os.urandom(rng.randrange(4096, 16384))
    if strategy == "underflow":
        return os.urandom(rng.randrange(0, 3))
    if strategy == "injection":
        return b"\x00" * 2 + b"A" * rng.randrange(16, 256)
    return os.urandom(rng.randrange(1, 512))  # random


def main(argv: list[str] | None = None) -> int:
    parser = base_parser("Fuzzing de protocolo por estrategias contra alvo de laboratorio.")
    parser.add_argument(
        "--strategy", choices=[*STRATEGIES, "all"], default="all",
        help="Estrategia de fuzzing (default: rotaciona todas).",
    )
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)

    def payload(seq: int) -> bytes:
        strat = args.strategy
        if strat == "all":
            strat = STRATEGIES[seq % len(STRATEGIES)]
        return _fuzz_payload(strat, seq, rng)

    sent = send_loop(args.transport, args.target, args.port, args.duration, args.rate, payload)
    run_and_report("fuzz", sent, args.target, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
