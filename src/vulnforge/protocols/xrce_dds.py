from ._probe import transport_probe
from .base import ProtocolPlugin


class XrceDdsPlugin(ProtocolPlugin):
    name = "XRCE-DDS"
    default_port = 8888
    transport = "udp"
    target_image = "iotedu-attack-xrce-dds-agent:latest"
    install_hint = "Uses a stdlib wire baseline; install Micro XRCE-DDS separately for a full agent."

    def baseline_message(self, seq: int) -> bytes:
        # Session header + CREATE_CLIENT payload: XRCE cookie, v1.0, eProsima vendor 0x010f.
        return bytes([0x81, 0x00]) + int(seq & 0xFFFF).to_bytes(2, "little") + b"\x00\x01\x0e\x00XRCE\x01\x00\x01\x0f\x00\x00"

    def health_probe(self, target: str, port: int | None = None):
        return transport_probe(target, port or self.default_port, self.transport)

