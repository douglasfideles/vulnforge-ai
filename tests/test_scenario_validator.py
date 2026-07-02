"""Tests for scenario YAML validation."""

import pytest

from vulnforge.models import AttackType, Scenario
from vulnforge.scenarios.schema import ScenarioValidationError, dump_scenario, load_scenario


def test_scenario_roundtrip(tmp_path):
    scenario = Scenario(
        scenario_id="xrce_dds_flooding",
        protocol="XRCE-DDS",
        attack_type=AttackType.FLOODING,
        output_pcap="out.pcap",
        label="xrce_dds_flooding",
    )
    path = dump_scenario(scenario, tmp_path / "s.yaml")
    loaded = load_scenario(path)
    assert loaded.scenario_id == scenario.scenario_id
    assert loaded.duration_seconds == 30


def test_invalid_duration():
    from pydantic import ValidationError
    with pytest.raises(ValidationError) as exc:
        Scenario(scenario_id="x", protocol="p", attack_type=AttackType.FLOODING, duration_seconds=0, output_pcap="o", label="l")
    assert "duration_seconds" in str(exc.value).lower()


def test_invalid_yaml_mapping(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("- not\n- a\n- mapping")
    with pytest.raises(ScenarioValidationError):
        load_scenario(path)
