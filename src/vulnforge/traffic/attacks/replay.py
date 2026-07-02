from pathlib import Path

from .common import run_and_report, synth_parser


def main():
    parser = synth_parser("Controlled byte replay (lab targets only)")
    parser.add_argument("--pcap", type=Path)
    args = parser.parse_args()
    payload = args.pcap.read_bytes()[:1400] if args.pcap else b"VULNFORGE-REPLAY"
    run_and_report(args, lambda seq: payload)


if __name__ == "__main__":
    main()

