"""Geracao de cenarios a partir de uma ThreatAnalysis."""

from __future__ import annotations

from ..models import AttackType, Scenario, ThreatAnalysis, Vulnerability

# Metadados por protocolo: porta + transporte do alvo no laboratorio.
PROTOCOL_PORTS: dict[str, tuple[int, str]] = {
    "XRCE-DDS": (8888, "udp"),
    "Zenoh": (7447, "tcp"),
    "DDS": (7400, "udp"),
}

# Mapa attack_type -> container existente do repo `ataques/` (reuso), por protocolo.
EXISTING_CONTAINERS: dict[str, dict[AttackType, str]] = {
    "XRCE-DDS": {
        AttackType.FLOODING: "iotedu-attack-xrce-dds-udp-dos",
        AttackType.MALFORMED_MESSAGE: "iotedu-attack-xrce-dds-malformed-inject",
        AttackType.REPLAY: "iotedu-attack-xrce-dds-session-hijack",
        AttackType.OVERSIZED_PAYLOAD: "iotedu-attack-xrce-dds-fragment-abuse",
        AttackType.INJECTION_SIMULATED: "iotedu-attack-xrce-dds-discovery-poison",
    },
    "Zenoh": {
        AttackType.FLOODING: "iotedu-attack-zenoh-pico-keepalive-flood",
        AttackType.MALFORMED_MESSAGE: "iotedu-attack-zenoh-pico-proto-fuzzer",
        AttackType.OVERSIZED_PAYLOAD: "iotedu-attack-zenoh-pico-memory-exhaustion",
        AttackType.REPLAY: "iotedu-attack-zenoh-pico-timestamp-mess",
    },
}

# attack_type -> modulo de ataque nativo Python do VulnForge.
NATIVE_ATTACK_MODULE: dict[AttackType, str] = {
    AttackType.FLOODING: "flooding",
    AttackType.REPLAY: "replay",
    AttackType.MALFORMED_MESSAGE: "malformed",
    AttackType.OVERSIZED_PAYLOAD: "oversized",
    AttackType.INJECTION_SIMULATED: "malformed",
}

DEFAULT_TARGET = "127.0.0.1"


def _slug(text: str) -> str:
    return text.lower().replace("-", "_").replace(" ", "_")


def _port_for(protocol: str) -> tuple[int, str]:
    return PROTOCOL_PORTS.get(protocol, (0, "udp"))


def _normal_command(protocol: str, target: str, port: int, transport: str) -> str:
    """Comando de trafego normal (baseline) via ataque nativo em modo benigno."""
    return (
        f"python -m vulnforge.traffic.attacks.flooding --target {target} --port {port} "
        f"--transport {transport} --rate 5 --duration 20 --benign"
    )


def _attack_command(
    protocol: str, attack: AttackType, target: str, port: int, transport: str,
    prefer_container: bool,
) -> str:
    """Comando de ataque: container existente (reuso) ou ataque nativo Python."""
    container = EXISTING_CONTAINERS.get(protocol, {}).get(attack)
    if prefer_container and container:
        return f"docker run --rm {container}:latest {target} {port}"

    module = NATIVE_ATTACK_MODULE.get(attack, "flooding")
    return (
        f"python -m vulnforge.traffic.attacks.{module} --target {target} --port {port} "
        f"--transport {transport} --duration 20"
    )


def generate(
    analysis: ThreatAnalysis,
    vuln: Vulnerability | None = None,
    target: str = DEFAULT_TARGET,
    interface: str = "any",
    duration: int = 30,
    prefer_container: bool = True,
) -> Scenario:
    """Constroi um Scenario a partir da analise. Reusa containers `ataques/` quando ha."""
    protocol = analysis.protocol
    attack = analysis.likely_attack_type
    if attack == AttackType.UNKNOWN:
        attack = AttackType.FLOODING  # default seguro/controlado para baseline de ataque

    port, transport = _port_for(protocol)
    if port == 0:
        port = 9999  # protocolo livre: porta placeholder, ajustar no YAML

    vuln_part = _slug(vuln.id) if vuln else _slug(protocol)
    scenario_id = f"{vuln_part}_{_slug(protocol)}_{attack.value}"
    label = analysis.dataset_label or f"{_slug(protocol)}_{attack.value}"
    pcap = f"data/runs/{scenario_id}.pcap"

    return Scenario(
        scenario_id=scenario_id,
        protocol=protocol,
        attack_type=attack,
        duration_seconds=duration,
        normal_traffic_command=_normal_command(protocol, target, port, transport),
        attack_command=_attack_command(protocol, attack, target, port, transport, prefer_container),
        capture_interface=interface,
        output_pcap=pcap,
        label=label,
        notes=(
            f"Gerado automaticamente. confidence={analysis.confidence:.2f}. "
            f"{analysis.safety_notes}"
        ),
    )
