"""Rule-based threat analysis from keyword heuristics."""

from __future__ import annotations

from ..models import AttackType, ThreatAnalysis

PROTOCOL_HINTS: dict[str, list[str]] = {
    "XRCE-DDS": ["xrce", "micro-xrce", "microxrce", "micro xrce", "uxr", "agent"],
    "Zenoh": ["zenoh"],
    "DDS": ["dds", "rtps", "fast dds", "fastdds", "cyclonedds", "data distribution"],
}

ATTACK_HINTS: list[tuple[AttackType, list[str]]] = [
    (
        AttackType.OVERSIZED_PAYLOAD,
        ["oversized", "large payload", "max frame", "65535", "buffer overflow", "oversize"],
    ),
    (
        AttackType.MALFORMED_MESSAGE,
        ["malformed", "fuzz", "parser", "invalid", "corrupt", "crafted", "fragment"],
    ),
    (
        AttackType.REPLAY,
        ["replay", "retransmit", "captured message", "session hijack", "spoof"],
    ),
    (
        AttackType.INJECTION_SIMULATED,
        ["injection", "inject", "poison", "tamper"],
    ),
    (
        AttackType.FLOODING,
        ["flood", "dos", "denial of service", "exhaust", "amplification", "keepalive", "udp flood"],
    ),
]


def _canonical_protocol(protocol_hint: str | None, text: str) -> str:
    if protocol_hint:
        cleaned = protocol_hint.strip().lower().replace("_", "-").replace(" ", "-")
        for canonical, terms in PROTOCOL_HINTS.items():
            for term in terms:
                if cleaned == term.replace(" ", "-"):
                    return canonical
        return protocol_hint.strip()
    lowered = text.lower()
    for canonical, terms in PROTOCOL_HINTS.items():
        for term in terms:
            if term in lowered:
                return canonical
    return "unknown"


def _detect_attack_type(text: str) -> tuple[AttackType, float]:
    lowered = text.lower()
    for attack, terms in ATTACK_HINTS:
        for term in terms:
            if term in lowered:
                return attack, 0.6
    return AttackType.UNKNOWN, 0.2


def _proto_slug(protocol: str) -> str:
    return protocol.lower().replace("-", "_").replace(" ", "_")


def analyze(text: str, protocol_hint: str | None = None) -> ThreatAnalysis:
    """Return a rule-based ThreatAnalysis from free text."""
    protocol = _canonical_protocol(protocol_hint, text)
    attack_type, confidence = _detect_attack_type(text)
    dataset_label = f"{_proto_slug(protocol)}_{attack_type.value}"
    safety_notes = (
        "Use apenas em ambiente de laboratorio isolado. "
        "Nao direcione para redes publicas."
    )
    return ThreatAnalysis(
        protocol=protocol,
        likely_attack_type=attack_type,
        preconditions="Alvo acessivel na rede de laboratorio; trafego base capturavel.",
        expected_network_behavior="Trafego anomalo para o protocolo identificado.",
        dataset_label=dataset_label,
        confidence=confidence,
        safety_notes=safety_notes,
        source="rules",
    )
