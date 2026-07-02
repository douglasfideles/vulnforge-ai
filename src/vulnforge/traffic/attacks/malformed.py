import random

from vulnforge.protocols.registry import get
from .common import run_and_report, synth_parser


def main():
    parser = synth_parser("Controlled malformed protocol traffic")
    parser.add_argument("--protocol", default="XRCE-DDS")
    args = parser.parse_args()
    plugin = get(args.protocol)
    rng = random.Random(1337)
    def factory(seq):
        base = bytearray(plugin.baseline_message(seq) if plugin else b"VULNFORGE")
        base[0] ^= 0xff
        return bytes(base) + rng.randbytes(8)
    run_and_report(args, factory)


if __name__ == "__main__":
    main()

