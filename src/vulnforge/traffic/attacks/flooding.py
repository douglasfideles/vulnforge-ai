from vulnforge.protocols.registry import get
from .common import run_and_report, synth_parser


def main():
    parser = synth_parser("Controlled baseline/flood traffic")
    parser.add_argument("--benign", action="store_true")
    parser.add_argument("--protocol", default="XRCE-DDS")
    args = parser.parse_args()
    plugin = get(args.protocol)
    factory = plugin.baseline_message if plugin else lambda seq: b"VULNFORGE" + seq.to_bytes(4, "little")
    run_and_report(args, factory)


if __name__ == "__main__":
    main()

