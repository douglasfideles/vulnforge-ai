from vulnforge.protocols.registry import get
from .common import run_and_report, synth_parser


def main():
    parser = synth_parser("Controlled oversized payload traffic")
    parser.add_argument("--protocol", default="XRCE-DDS")
    args = parser.parse_args()
    plugin = get(args.protocol)
    base = plugin.baseline_message(0) if plugin else b"VULNFORGE"
    run_and_report(args, lambda seq: base + b"\xff" * min(60000, 65507-len(base)))


if __name__ == "__main__":
    main()

