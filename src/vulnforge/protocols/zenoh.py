import importlib.util

from ._probe import transport_probe
from .base import ProtocolPlugin


class ZenohPlugin(ProtocolPlugin):
    name = "Zenoh"
    default_port = 7447
    transport = "tcp"
    target_image = "eclipse/zenoh:latest"
    install_hint = "pip install 'vulnforge-ai[zenoh]' for stronger Zenoh integration"

    def is_available(self) -> bool:
        return importlib.util.find_spec("zenoh") is not None

    def baseline_message(self, seq: int) -> bytes:
        payload = b"\x01" + int(seq & 0xFFFFFFFF).to_bytes(4, "little")
        return len(payload).to_bytes(2, "little") + payload

    def health_probe(self, target: str, port: int | None = None):
        return transport_probe(target, port or self.default_port, self.transport)

