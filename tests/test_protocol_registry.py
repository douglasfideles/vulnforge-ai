"""Testes do registro plugavel de protocolos."""

from vulnforge.models import ProbeResult
from vulnforge.protocols import registry
from vulnforge.protocols.base import ProtocolPlugin


def test_builtin_protocols_registered():
    av = registry.available()
    assert registry.get("XRCE-DDS") is not None
    assert registry.get("zenoh") is not None       # case/sep-insensitive
    assert registry.get("DDS") is not None
    assert len(av) >= 3


def test_get_is_normalized():
    assert registry.get("xrce_dds") is registry.get("XRCE-DDS")


def test_baseline_messages_are_protocol_shaped():
    xrce = registry.get("XRCE-DDS").baseline_message(0)
    assert b"XRCE" in xrce                           # cookie real do XRCE (no payload)
    dds = registry.get("DDS").baseline_message(0)
    assert dds[:4] == b"RTPS"                        # magic RTPS real (no header)


def test_register_custom_plugin():
    class FakePlugin(ProtocolPlugin):
        name = "FakeProto"
        default_port = 12345
        transport = "udp"

        def baseline_message(self, seq):
            return b"FAKE" + bytes([seq & 0xFF])

        def health_probe(self, target, port=None):
            return ProbeResult(responsive=True, detail="fake up")

    registry.register(FakePlugin())
    p = registry.get("fakeproto")
    assert p is not None
    assert p.baseline_message(1) == b"FAKE\x01"
    assert p.capture_filter() == "udp port 12345"
