"""Testes da analise de PCAP (anomalias indicativas de efeito)."""

import pytest

from vulnforge.validation.pcap_analysis import analyze_pcap

scapy = pytest.importorskip("scapy.all")


def _write_pcap(path, packets):
    scapy.wrpcap(str(path), packets)


def test_counts_rst_and_icmp(tmp_path):
    target = "127.0.0.1"
    pkts = [
        scapy.IP(src="127.0.0.2", dst=target) / scapy.UDP(dport=8888),       # para alvo
        scapy.IP(src=target, dst="127.0.0.2") / scapy.TCP(flags="R"),         # RST do alvo
        scapy.IP(src=target, dst="127.0.0.2") / scapy.ICMP(type=3),           # unreachable
    ]
    pcap = tmp_path / "c.pcap"
    _write_pcap(pcap, pkts)

    stats = analyze_pcap(pcap, target=target)
    assert stats.packets_total == 3
    assert stats.tcp_rst == 1
    assert stats.icmp_unreachable == 1
    assert any("RST" in a for a in stats.anomalies)
    assert any("ICMP" in a for a in stats.anomalies)


def test_missing_pcap_is_graceful(tmp_path):
    stats = analyze_pcap(tmp_path / "nope.pcap", target="127.0.0.1")
    assert stats.packets_total == 0
    assert "nao encontrado" in stats.note
