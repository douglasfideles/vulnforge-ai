"""Tests for rule-based threat analyzer."""

from vulnforge.llm.rules import analyze
from vulnforge.models import AttackType


def test_xrce_flooding():
    text = "XRCE-DDS agent crashes due to UDP flood exhaustion"
    result = analyze(text)
    assert result.protocol == "XRCE-DDS"
    assert result.likely_attack_type == AttackType.FLOODING
    assert result.dataset_label == "xrce_dds_flooding"
    assert result.confidence == 0.6
    assert result.source == "rules"


def test_zenoh_malformed():
    text = "Zenoh router parser fails on malformed frames"
    result = analyze(text, protocol_hint="Zenoh")
    assert result.protocol == "Zenoh"
    assert result.likely_attack_type == AttackType.MALFORMED_MESSAGE


def test_dds_replay():
    text = "RTPS captured messages can be replayed to hijack session"
    result = analyze(text)
    assert result.protocol == "DDS"
    assert result.likely_attack_type == AttackType.REPLAY


def test_unknown():
    result = analyze("some random description without clues")
    assert result.likely_attack_type == AttackType.UNKNOWN
    assert result.confidence == 0.2
