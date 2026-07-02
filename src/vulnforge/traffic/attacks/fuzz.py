import random

from vulnforge.protocols.registry import get
from .common import run_and_report, synth_parser


def main():
    parser = synth_parser("Seeded, bounded protocol fuzzing")
    parser.add_argument("--protocol", default="XRCE-DDS")
    args = parser.parse_args()
    plugin, rng = get(args.protocol), random.Random(1337)
    def factory(seq):
        value = bytearray(plugin.baseline_message(seq) if plugin else b"VULNFORGE")
        value[rng.randrange(len(value))] ^= 1 << rng.randrange(8)
        return bytes(value)
    run_and_report(args, factory)


if __name__ == "__main__":
    main()

