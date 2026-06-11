"""Testes da logica de veredito do harness de validacao."""

from vulnforge.models import ProbeResult
from vulnforge.validation.harness import build_report, decide_verdict
from vulnforge.validation.pcap_analysis import PcapStats


def _resp(ok: bool) -> ProbeResult:
    return ProbeResult(responsive=ok, detail="x")


def test_was_up_now_down_is_valid():
    assert decide_verdict(_resp(True), _resp(False), PcapStats()) == "valid"


def test_anomalies_make_it_valid():
    stats = PcapStats(anomalies=["3 TCP RST"])
    assert decide_verdict(_resp(True), _resp(True), stats) == "valid"


def test_up_and_still_up_no_anomaly_is_invalid():
    assert decide_verdict(_resp(True), _resp(True), PcapStats()) == "invalid"


def test_unknown_states_are_inconclusive():
    assert decide_verdict(None, None, PcapStats()) == "inconclusive"
    assert decide_verdict(_resp(False), _resp(False), PcapStats()) == "inconclusive"


def test_build_report_fills_fields():
    report = build_report(_resp(True), _resp(False), pcap_path=None, target="127.0.0.1",
                          packets_out=100)
    assert report.verdict == "valid"
    assert report.responsive_before is True
    assert report.responsive_after is False
    assert report.packets_out == 100
