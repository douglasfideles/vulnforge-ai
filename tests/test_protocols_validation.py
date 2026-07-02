import pytest

from vulnforge.models import ProbeResult
from vulnforge.protocols.registry import available, get, load_builtin
from vulnforge.validation.harness import decide_verdict
from vulnforge.validation.pcap_analysis import analyze_pcap


def test_registry_idempotent_and_normalized():
    load_builtin()
    before = len(available())
    load_builtin()
    assert len(available()) == before == 3
    assert get("xrce_dds").name == "XRCE-DDS"


def test_protocol_wire_framing():
    assert b"XRCE" in get("XRCE-DDS").baseline_message(1)
    assert get("DDS").baseline_message(1).startswith(b"RTPS")
    assert len(get("Zenoh").baseline_message(1)) > 4


@pytest.mark.parametrize(("name", "filter"), [("DDS", "udp port 7400"), ("Zenoh", "tcp port 7447"), ("XRCE-DDS", "udp port 8888")])
def test_capture_filters(name, filter):
    assert get(name).capture_filter() == filter


@pytest.mark.parametrize(
    ("before", "after", "anomalies", "expected"),
    [
        (True, False, [], "valid"),
        (False, False, ["TCP RST"], "valid"),
        (True, True, [], "invalid"),
        (None, None, [], "inconclusive"),
    ],
)
def test_verdict_rules(before, after, anomalies, expected):
    b = ProbeResult(responsive=before) if before is not None else None
    a = ProbeResult(responsive=after) if after is not None else None
    assert decide_verdict(b, a, {"anomalies": anomalies}).verdict == expected


def test_missing_pcap_degrades(tmp_path):
    stats = analyze_pcap(tmp_path / "none.pcap", "127.0.0.1")
    assert stats["total_packets"] == 0
    assert "missing" in stats["note"]

