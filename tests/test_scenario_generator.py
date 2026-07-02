"""Tests for scenario generator."""

from vulnforge.models import AttackType, ThreatAnalysis
from vulnforge.scenarios.generator import generate


def test_generate_xrce_flooding_container():
    analysis = ThreatAnalysis(
        protocol="XRCE-DDS",
        likely_attack_type=AttackType.FLOODING,
        dataset_label="xrce_dds_flooding",
    )
    scenario = generate(analysis, target="127.0.0.1", prefer_container=True)
    assert scenario.protocol == "XRCE-DDS"
    assert scenario.attack_type == AttackType.FLOODING
    assert "iotedu-attack-xrce-dds-udp-dos" in scenario.attack_command
    assert "--benign" in scenario.normal_traffic_command


def test_generate_native():
    analysis = ThreatAnalysis(
        protocol="Zenoh",
        likely_attack_type=AttackType.MALFORMED_MESSAGE,
    )
    scenario = generate(analysis, target="127.0.0.1", prefer_container=False)
    assert "python -m vulnforge.traffic.attacks.malformed" in scenario.attack_command
    assert "7447" in scenario.attack_command


def test_unknown_protocol_defaults():
    analysis = ThreatAnalysis(protocol="unknown", likely_attack_type=AttackType.FLOODING)
    scenario = generate(analysis)
    assert scenario.attack_command.startswith("python -m")
