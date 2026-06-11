"""Testes da validacao de cenarios."""

import pytest

from vulnforge.scenarios.schema import (
    ScenarioValidationError,
    dump_scenario,
    load_scenario,
    validate_scenario,
)

VALID = {
    "scenario_id": "t1",
    "protocol": "XRCE-DDS",
    "attack_type": "flooding",
    "duration_seconds": 30,
    "normal_traffic_command": "echo normal",
    "attack_command": "echo attack",
    "capture_interface": "any",
    "output_pcap": "data/runs/t1.pcap",
    "label": "xrce_dds_flooding",
    "notes": "",
}


def test_valid_scenario_passes():
    s = validate_scenario(VALID)
    assert s.scenario_id == "t1"
    assert s.attack_type.value == "flooding"


def test_missing_required_field_raises():
    data = dict(VALID)
    del data["output_pcap"]
    with pytest.raises(ScenarioValidationError):
        validate_scenario(data)


def test_invalid_attack_type_raises():
    data = dict(VALID, attack_type="nao_existe")
    with pytest.raises(ScenarioValidationError):
        validate_scenario(data)


def test_negative_duration_raises():
    data = dict(VALID, duration_seconds=-5)
    with pytest.raises(ScenarioValidationError):
        validate_scenario(data)


def test_roundtrip_yaml(tmp_path):
    s = validate_scenario(VALID)
    path = tmp_path / "s.yaml"
    dump_scenario(s, path)
    loaded = load_scenario(path)
    assert loaded.scenario_id == s.scenario_id
    assert loaded.attack_type == s.attack_type


def test_example_scenarios_are_valid():
    import glob

    for yaml_file in glob.glob("scenarios/examples/*.yaml"):
        load_scenario(yaml_file)  # nao deve levantar
