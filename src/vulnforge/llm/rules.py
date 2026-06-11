"""Analisador rule-based offline: heuristicas por palavras-chave.

Usado como fallback quando nao ha LLM configurado ou a saida do LLM e invalida.
Nao depende de rede.
"""

from __future__ import annotations

from ..models import AttackType, ThreatAnalysis

# protocolo -> termos que sugerem o protocolo
_PROTOCOL_HINTS: dict[str, tuple[str, ...]] = {
    "XRCE-DDS": ("xrce", "micro-xrce", "microxrce", "micro xrce", "uxr", "agent"),
    "Zenoh": ("zenoh",),
    "DDS": ("dds", "rtps", "fast dds", "fastdds", "cyclonedds", "data distribution"),
}

# attack_type -> termos que sugerem o tipo de ataque (ordem = prioridade)
_ATTACK_HINTS: list[tuple[AttackType, tuple[str, ...]]] = [
    (AttackType.OVERSIZED_PAYLOAD, ("oversized", "large payload", "max frame", "65535", "buffer overflow", "oversize")),
    (AttackType.MALFORMED_MESSAGE, ("malformed", "fuzz", "parser", "invalid", "corrupt", "crafted", "fragment")),
    (AttackType.REPLAY, ("replay", "retransmit", "captured message", "session hijack", "spoof")),
    (AttackType.INJECTION_SIMULATED, ("injection", "inject", "poison", "tamper")),
    (AttackType.FLOODING, ("flood", "dos", "denial of service", "exhaust", "amplification", "keepalive", "udp flood")),
]

_EXPECTED_BEHAVIOR: dict[AttackType, str] = {
    AttackType.FLOODING: "Alto volume de pacotes/conexoes por segundo; crescimento de uso de CPU/memoria no alvo; possivel perda de pacotes legitimos.",
    AttackType.REPLAY: "Mensagens duplicadas com timestamps/sequencias repetidos; reaparecimento de payloads previamente capturados.",
    AttackType.MALFORMED_MESSAGE: "Pacotes com headers/campos invalidos; respostas de erro ou ausencia de resposta; possiveis reinicializacoes do parser.",
    AttackType.OVERSIZED_PAYLOAD: "Pacotes proximos ao MTU/maximo do protocolo; fragmentacao; pressao de memoria no buffer de reassembly.",
    AttackType.INJECTION_SIMULATED: "Entidades/mensagens nao autorizadas aparecendo no barramento; divergencia entre estado esperado e observado.",
    AttackType.UNKNOWN: "Comportamento nao caracterizado; capturar baseline e comparar.",
}


def _detect_protocol(text: str, hint: str | None) -> str:
    if hint:
        for canon in _PROTOCOL_HINTS:
            if hint.lower().replace("_", "-") in canon.lower() or canon.lower() in hint.lower():
                return canon
        return hint  # protocolo livre fornecido pelo usuario
    for canon, terms in _PROTOCOL_HINTS.items():
        if any(t in text for t in terms):
            return canon
    return "unknown"


def _detect_attack(text: str) -> tuple[AttackType, float]:
    for attack, terms in _ATTACK_HINTS:
        if any(t in text for t in terms):
            return attack, 0.6
    return AttackType.UNKNOWN, 0.2


def analyze(text: str, protocol_hint: str | None = None) -> ThreatAnalysis:
    """Heuristica offline. Retorna ThreatAnalysis com source='rules'."""
    low = (text or "").lower()
    protocol = _detect_protocol(low, protocol_hint)
    attack, confidence = _detect_attack(low)

    proto_slug = protocol.lower().replace("-", "_").replace(" ", "_")
    dataset_label = f"{proto_slug}_{attack.value}" if attack != AttackType.UNKNOWN else f"{proto_slug}_unknown"

    return ThreatAnalysis(
        protocol=protocol,
        likely_attack_type=attack,
        preconditions=(
            "Laboratorio isolado com o broker/agent alvo em execucao e alcancavel; "
            "trafego normal de baseline disponivel para comparacao."
        ),
        expected_network_behavior=_EXPECTED_BEHAVIOR[attack],
        dataset_label=dataset_label,
        confidence=confidence,
        safety_notes=(
            "Cenario exclusivamente para laboratorio controlado. Nao executar contra alvos "
            "de producao ou redes publicas. Alvo deve ser IP privado/loopback."
        ),
        source="rules",
    )
