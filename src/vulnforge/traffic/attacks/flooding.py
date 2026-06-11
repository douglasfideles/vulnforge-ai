"""Flooding controlado UDP/TCP. Em modo --benign serve como trafego de baseline."""

from __future__ import annotations

import os

from .common import base_parser, run_and_report, send_loop


def main(argv: list[str] | None = None) -> int:
    parser = base_parser("Flooding controlado de pacotes contra alvo de laboratorio.")
    parser.add_argument("--size", type=int, default=64, help="Tamanho do payload em bytes")
    parser.add_argument(
        "--benign", action="store_true",
        help="Trafego de baseline (rate baixo, payload pequeno) em vez de flood agressivo.",
    )
    args = parser.parse_args(argv)

    size = 32 if args.benign else args.size
    seed = os.urandom(max(1, min(size, 4)))

    def payload(seq: int) -> bytes:
        body = seed + seq.to_bytes(4, "big")
        return (body * (size // len(body) + 1))[:size]

    sent = send_loop(args.transport, args.target, args.port, args.duration, args.rate, payload)
    label = "baseline" if args.benign else "flooding"
    run_and_report(label, sent, args.target, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
