"""Tests for effect validation harness."""

from vulnforge.models import ProbeResult
from vulnforge.validation.harness import decide_verdict
from vulnforge.validation.pcap_analysis import PcapStats


def test_verdict_responsive_before_not_after():
    before = ProbeResult(responsive=True)
    after = ProbeResult(responsive=False)
    report = decide_verdict(before, after, PcapStats())
    assert report.verdict == "valid"


def test_verdict_pcap_anomaly():
    before = ProbeResult(responsive=True)
    after = ProbeResult(responsive=True)
    stats = PcapStats(tcp_rst=1)
    report = decide_verdict(before, after, stats)
    assert report.verdict == "valid"
    assert "TCP RST" in report.anomalies[0]


def test_verdict_invalid():
    before = ProbeResult(responsive=True)
    after = ProbeResult(responsive=True)
    report = decide_verdict(before, after, PcapStats())
    assert report.verdict == "invalid"


def test_verdict_inconclusive():
    before = ProbeResult(responsive=False)
    after = ProbeResult(responsive=False)
    report = decide_verdict(before, after, PcapStats())
    assert report.verdict == "inconclusive"
