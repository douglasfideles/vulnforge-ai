from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from vulnforge.models import AttackType, Scenario, ThreatAnalysis

PORTS = {"XRCE-DDS": (8888, "udp"), "Zenoh": (7447, "tcp"), "DDS": (7400, "udp")}
CONTAINERS = {
    ("XRCE-DDS", AttackType.flooding): "iotedu-attack-xrce-dds-udp-dos",
    ("Zenoh", AttackType.flooding): "iotedu-attack-zenoh-pico-keepalive-flood",
    ("XRCE-DDS", AttackType.malformed_message): "iotedu-attack-xrce-dds-malformed-inject",
    ("Zenoh", AttackType.malformed_message): "iotedu-attack-zenoh-pico-proto-fuzzer",
    ("XRCE-DDS", AttackType.replay): "iotedu-attack-xrce-dds-session-hijack",
    ("Zenoh", AttackType.replay): "iotedu-attack-zenoh-pico-timestamp-mess",
    ("XRCE-DDS", AttackType.oversized_payload): "iotedu-attack-xrce-dds-fragment-abuse",
    ("Zenoh", AttackType.oversized_payload): "iotedu-attack-zenoh-pico-memory-exhaustion",
    ("XRCE-DDS", AttackType.injection_simulated): "iotedu-attack-xrce-dds-discovery-poison",
}
MODULES = {
    AttackType.flooding: "flooding", AttackType.replay: "replay",
    AttackType.malformed_message: "malformed", AttackType.oversized_payload: "oversized",
    AttackType.injection_simulated: "malformed", AttackType.unknown: "fuzz",
}


class ScenarioValidationError(ValueError):
    pass


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", value.lower().replace("-", "_")).strip("_")


def generate_scenario(
    analysis: ThreatAnalysis, target: str = "127.0.0.1", interface: str = "any",
    duration: int = 30, native: bool = False
) -> Scenario:
    port, transport = PORTS.get(analysis.protocol, (0, "udp"))
    quoted = shlex.quote(target)
    python = shlex.quote(sys.executable)
    base_args = f"--target {quoted} --port {port} --transport {transport}"
    normal = f"{python} -m vulnforge.traffic.attacks.flooding {base_args} --rate 5 --duration 20 --benign"
    image = CONTAINERS.get((analysis.protocol, analysis.likely_attack_type))
    if image and not native:
        attack = f"docker run --rm --network host {image} --target {quoted} --port {port}"
    else:
        module = MODULES.get(analysis.likely_attack_type, "fuzz")
        attack = (
            f"{python} -m vulnforge.traffic.attacks.{module} {base_args} "
            f"--duration {duration} --rate 20"
        )
    scenario_id = _slug(analysis.dataset_label)
    return Scenario(
        scenario_id=scenario_id, protocol=analysis.protocol,
        attack_type=analysis.likely_attack_type, duration_seconds=duration,
        normal_traffic_command=normal, attack_command=attack,
        capture_interface=interface,
        output_pcap=f"data/runs/{scenario_id}.pcap",
        label=analysis.dataset_label,
        notes="Controlled laboratory scenario; dry-run by default.",
    )


def save_scenario(scenario: Scenario, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(scenario.model_dump(mode="json"), sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def load_scenario(path: str | Path) -> Scenario:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ScenarioValidationError("Cenario invalido: top-level value must be a mapping")
        return Scenario.model_validate(data)
    except ValidationError as exc:
        issues = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise ScenarioValidationError(f"Cenario invalido: {issues}") from None
    except yaml.YAMLError as exc:
        raise ScenarioValidationError(f"Cenario invalido: YAML: {exc}") from None

