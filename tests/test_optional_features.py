import asyncio
import sys
from types import ModuleType, SimpleNamespace

import pytest


def test_api_is_read_only_and_generates_scenario(monkeypatch):
    pytest.importorskip("fastapi")
    import httpx
    from vulnforge.api import app

    async def exercise_api():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://artifact") as client:
            assert (await client.get("/health")).json() == {"status": "ok"}
            analysis = await client.post(
                "/analyze", json={"text": "XRCE agent denial of service resource exhaustion"}
            )
            assert analysis.status_code == 200
            assert analysis.json()["likely_attack_type"] == "flooding"
            scenario = await client.post(
                "/generate-scenario", json={"text": "DDS malformed parser input"}
            )
            assert scenario.status_code == 200
            assert scenario.json()["attack_type"] == "malformed_message"

    asyncio.run(exercise_api())
    routes = {route.path for route in app.routes}
    assert not any("run" in route for route in routes)


def test_pcap_analysis_counts_effect_indicators(tmp_path, monkeypatch):
    class IP: ...
    class TCP: ...
    class ICMP: ...

    class Packet:
        def __init__(self, **layers):
            self.layers = layers

        def __contains__(self, layer):
            return layer.__name__ in self.layers

        def __getitem__(self, layer):
            return self.layers[layer.__name__]

    packets = [
        Packet(IP=SimpleNamespace(src="10.0.0.2", dst="10.0.0.1"), TCP=SimpleNamespace(flags=0x02)),
        Packet(IP=SimpleNamespace(src="10.0.0.1", dst="10.0.0.2"), TCP=SimpleNamespace(flags=0x04)),
        Packet(IP=SimpleNamespace(src="10.0.0.1", dst="10.0.0.2"), ICMP=SimpleNamespace(type=3)),
    ]
    fake = ModuleType("scapy.all")
    fake.IP, fake.TCP, fake.ICMP = IP, TCP, ICMP
    fake.rdpcap = lambda path: packets
    package = ModuleType("scapy")
    package.all = fake
    monkeypatch.setitem(sys.modules, "scapy", package)
    monkeypatch.setitem(sys.modules, "scapy.all", fake)

    from vulnforge.validation.pcap_analysis import analyze_pcap

    pcap = tmp_path / "effect.pcap"
    pcap.write_bytes(b"test")
    stats = analyze_pcap(pcap, "10.0.0.1")
    assert stats["total_packets"] == 3
    assert stats["packets_out"] == 1
    assert stats["packets_in"] == 2
    assert stats["tcp_rst"] == 1
    assert stats["icmp_unreachable"] == 1
    assert len(stats["anomalies"]) == 2


def test_pcap_analysis_degrades_when_scapy_cannot_initialize(tmp_path, monkeypatch):
    fake = ModuleType("scapy.all")
    # A module without the required names reproduces an unavailable/broken optional dependency.
    package = ModuleType("scapy")
    package.all = fake
    monkeypatch.setitem(sys.modules, "scapy", package)
    monkeypatch.setitem(sys.modules, "scapy.all", fake)
    from vulnforge.validation.pcap_analysis import analyze_pcap

    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"test")
    stats = analyze_pcap(pcap, "127.0.0.1")
    assert stats["total_packets"] == 0
    assert "Scapy unavailable" in stats["note"]
