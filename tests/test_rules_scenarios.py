import pytest

from vulnforge.llm.rules import analyze_rules, canonical_protocol
from vulnforge.models import AttackType
from vulnforge.scenarios.generator import ScenarioValidationError, generate_scenario, load_scenario, save_scenario


@pytest.mark.parametrize(
    ("text", "attack"),
    [
        ("buffer overflow with oversized frame", AttackType.oversized_payload),
        ("crafted malformed parser input", AttackType.malformed_message),
        ("captured message replay", AttackType.replay),
        ("discovery poison injection", AttackType.injection_simulated),
        ("resource exhaustion denial of service", AttackType.flooding),
        ("unrelated observation", AttackType.unknown),
    ],
)
def test_attack_rules(text, attack):
    result = analyze_rules(text, "XRCE-DDS")
    assert result.likely_attack_type == attack
    assert result.confidence == (0.2 if attack == AttackType.unknown else 0.6)


@pytest.mark.parametrize(("hint", "expected"), [("micro_xrce", "XRCE-DDS"), ("ZENOH", "Zenoh"), ("fastdds", "DDS"), ("custom", "custom")])
def test_protocol_canonicalization(hint, expected):
    assert canonical_protocol(hint) == expected


def test_scenario_round_trip(tmp_path):
    analysis = analyze_rules("XRCE UDP flood")
    scenario = generate_scenario(analysis, native=True, duration=12)
    path = save_scenario(scenario, tmp_path / "s.yaml")
    loaded = load_scenario(path)
    assert loaded == scenario
    assert "--target 127.0.0.1" in loaded.attack_command
    assert "attacks.flooding" in loaded.attack_command


def test_scenario_container_default():
    scenario = generate_scenario(analyze_rules("Zenoh keepalive flood"))
    assert "docker run" in scenario.attack_command
    assert scenario.output_pcap.endswith(".pcap")


@pytest.mark.parametrize(
    "yaml_text",
    ["- not\n- mapping\n", "protocol: DDS\nattack_type: flooding\n", "scenario_id: x\nprotocol: DDS\nattack_type: flooding\nduration_seconds: 0\noutput_pcap: x\nlabel: x\n"],
)
def test_readable_scenario_errors(tmp_path, yaml_text):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml_text)
    with pytest.raises(ScenarioValidationError, match="Cenario invalido"):
        load_scenario(path)

