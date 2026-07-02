"""Generate Scenario YAML from ThreatAnalysis."""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import AttackType, Scenario, ThreatAnalysis, Vulnerability
from ..protocols import registry

CONTAINERS: dict[str, dict[str, str]] = {
    "flooding": {
        "XRCE-DDS": "iotedu-attack-xrce-dds-udp-dos",
        "Zenoh": "iotedu-attack-zenoh-pico-keepalive-flood",
    },
    "malformed_message": {
        "XRCE-DDS": "iotedu-attack-xrce-dds-malformed-inject",
        "Zenoh": "iotedu-attack-zenoh-pico-proto-fuzzer",
    },
    "replay": {
        "XRCE-DDS": "iotedu-attack-xrce-dds-session-hijack",
        "Zenoh": "iotedu-attack-zenoh-pico-timestamp-mess",
    },
    "oversized_payload": {
        "XRCE-DDS": "iotedu-attack-xrce-dds-fragment-abuse",
        "Zenoh": "iotedu-attack-zenoh-pico-memory-exhaustion",
    },
    "injection_simulated": {
        "XRCE-DDS": "iotedu-attack-xrce-dds-discovery-poison",
    },
}

NATIVE_MODULE: dict[str, str] = {
    "flooding": "flooding",
    "replay": "replay",
    "malformed_message": "malformed",
    "oversized_payload": "oversized",
    "injection_simulated": "malformed",
}

PROTOCOL_DEFAULTS: dict[str, tuple[int, str]] = {
    "XRCE-DDS": (8888, "udp"),
    "Zenoh": (7447, "tcp"),
    "DDS": (7400, "udp"),
}


def _slug(value: str) -> str:
    return value.lower().replace("-", "_").replace(" ", "_")


def _port_transport(protocol: str) -> tuple[int, str]:
    canonical = protocol.strip()
    for key, (port, transport) in PROTOCOL_DEFAULTS.items():
        if canonical.lower() == key.lower():
            return port, transport
    return 0, "udp"


def _normal_traffic_command(target: str, port: int, transport: str) -> str:
    return (
        f"python -m vulnforge.traffic.attacks.flooding "
        f"--target {target} --port {port} --transport {transport} "
        f"--rate 5 --duration 20 --benign"
    )


def generate(
    analysis: ThreatAnalysis,
    vuln: Vulnerability | None = None,
    target: str = "127.0.0.1",
    interface: str = "any",
    duration: int = 30,
    prefer_container: bool = True,
) -> Scenario:
    """Generate a Scenario from a ThreatAnalysis."""
    protocol = analysis.protocol or "unknown"
    attack_type = analysis.likely_attack_type
    port, transport = _port_transport(protocol)

    scenario_id = f"{_slug(protocol)}_{_slug(attack_type.value)}"
    label = analysis.dataset_label or scenario_id

    normal_cmd = _normal_traffic_command(target, port, transport)

    attack_cmd = ""
    if prefer_container:
        container = CONTAINERS.get(attack_type.value, {}).get(protocol)
        if container:
            attack_cmd = (
                f"docker run --rm --net=host {container} "
                f"--target {target} --port {port} --transport {transport} --duration {duration}"
            )
    if not attack_cmd:
        module = NATIVE_MODULE.get(attack_type.value, "fuzz")
        attack_cmd = (
            f"python -m vulnforge.traffic.attacks.{module} "
            f"--target {target} --port {port} --transport {transport} --duration {duration}"
        )

    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output_pcap = f"data/runs/{scenario_id}_{now}.pcap"

    notes = (
        f"Generated from analysis (confidence={analysis.confidence:.2f}). "
        f"{analysis.safety_notes}"
    )

    return Scenario(
        scenario_id=scenario_id,
        protocol=protocol,
        attack_type=attack_type,
        duration_seconds=duration,
        normal_traffic_command=normal_cmd,
        attack_command=attack_cmd,
        capture_interface=interface,
        output_pcap=output_pcap,
        label=label,
        notes=notes,
    )
