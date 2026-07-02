import importlib.util

from ._probe import transport_probe
from .base import ProtocolPlugin


class DdsPlugin(ProtocolPlugin):
    name = "DDS"
    default_port = 7400
    transport = "udp"
    target_image = None
    install_hint = "pip install 'vulnforge-ai[dds]' for CycloneDDS integration"

    def is_available(self) -> bool:
        return importlib.util.find_spec("cyclonedds") is not None

    def baseline_message(self, seq: int) -> bytes:
        # RTPS v2.3, eProsima vendor, deterministic 12-byte GUID prefix.
        return b"RTPS\x02\x03\x01\x0f" + int(seq).to_bytes(4, "big", signed=False) + b"\x00" * 8

    def health_probe(self, target: str, port: int | None = None):
        return transport_probe(target, port or self.default_port, self.transport)

