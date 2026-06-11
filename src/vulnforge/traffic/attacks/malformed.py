"""Mensagens malformadas / fuzzing leve de bytes para testar robustez do parser."""

from __future__ import annotations

import os
import random

from .common import base_parser, run_and_report, send_loop

# Sementes de headers plausiveis para corromper (XRCE-DDS / Zenoh framing).
_HEADER_SEEDS = [
    bytes([0x80, 0x00, 0x00, 0x00]),  # XRCE session header-ish
    bytes([0x00, 0x20]),               # Zenoh frame + reliable flag
    bytes([0x01, 0xFF, 0xFF, 0xFF]),
]


def _mutate(seed: bytes, size: int, rng: random.Random) -> bytes:
    buf = bytearray(seed + os.urandom(max(0, size - len(seed))))
    # Corrompe alguns bytes aleatorios.
    for _ in range(max(1, len(buf) // 8)):
        idx = rng.randrange(len(buf))
        buf[idx] = rng.randrange(256)
    return bytes(buf)


def main(argv: list[str] | None = None) -> int:
    parser = base_parser("Envio de mensagens malformadas/fuzz contra alvo de laboratorio.")
    parser.add_argument("--size", type=int, default=128, help="Tamanho base do payload (bytes)")
    parser.add_argument("--seed", type=int, default=1337, help="Seed do RNG (reproducibilidade)")
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)

    def payload(seq: int) -> bytes:
        seed = _HEADER_SEEDS[seq % len(_HEADER_SEEDS)]
        return _mutate(seed, args.size, rng)

    sent = send_loop(args.transport, args.target, args.port, args.duration, args.rate, payload)
    run_and_report("malformed", sent, args.target, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
