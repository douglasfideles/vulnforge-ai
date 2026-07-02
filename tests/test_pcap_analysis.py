"""Tests for PCAP analysis."""

from pathlib import Path

import pytest

from vulnforge.validation.pcap_analysis import PcapStats, analyze_pcap


def test_missing_pcap():
    stats = analyze_pcap("/nonexistent/file.pcap")
    assert "nao encontrado" in stats["note"]


def test_empty_stats_defaults():
    stats = PcapStats()
    assert stats["total_packets"] == 0
    assert stats["tcp_rst"] == 0


def test_note_set():
    stats = PcapStats(note="test")
    assert stats["note"] == "test"
