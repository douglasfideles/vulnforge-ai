import re

from vulnforge.models import AttackType, ThreatAnalysis

PROTOCOLS = {
    "XRCE-DDS": ("xrce", "micro-xrce", "microxrce", "micro xrce", "uxr", "agent"),
    "Zenoh": ("zenoh",),
    "DDS": ("dds", "rtps", "fast dds", "fastdds", "cyclonedds", "data distribution"),
}
ATTACKS = [
    (AttackType.oversized_payload, ("oversized", "large payload", "max frame", "65535", "buffer overflow", "oversize")),
    (AttackType.malformed_message, ("malformed", "fuzz", "parser", "invalid", "corrupt", "crafted", "fragment")),
    (AttackType.replay, ("replay", "retransmit", "captured message", "session hijack", "spoof")),
    (AttackType.injection_simulated, ("injection", "inject", "poison", "tamper")),
    (AttackType.flooding, ("flood", "dos", "denial of service", "exhaust", "amplification", "keepalive", "udp flood")),
]


def canonical_protocol(hint: str, text: str = "") -> str:
    candidate = hint.strip().lower().replace("_", "-")
    haystack = candidate or text.lower()
    for protocol, terms in PROTOCOLS.items():
        if any(term in haystack for term in terms):
            return protocol
    return hint.strip() or "unknown"


def analyze_rules(text: str, protocol_hint: str = "") -> ThreatAnalysis:
    protocol = canonical_protocol(protocol_hint, text)
    lower = text.lower()
    attack = AttackType.unknown
    for candidate, terms in ATTACKS:
        if any(term in lower for term in terms):
            attack = candidate
            break
    slug = re.sub(r"[-\s]+", "_", protocol.lower())
    return ThreatAnalysis(
        protocol=protocol,
        likely_attack_type=attack,
        preconditions="Isolated laboratory target reachable on the protocol transport.",
        expected_network_behavior=f"Controlled {attack.value} traffic against a lab-only endpoint.",
        dataset_label=f"{slug}_{attack.value}",
        confidence=0.6 if attack != AttackType.unknown else 0.2,
        safety_notes="Use only an isolated lab target in an authorized environment.",
        source="rules",
    )

