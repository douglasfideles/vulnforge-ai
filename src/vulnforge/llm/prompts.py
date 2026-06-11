"""Prompts para o Threat Analyzer baseado em LLM."""

from __future__ import annotations

SYSTEM_PROMPT = (
    "Voce e um analista de seguranca de protocolos IoT (DDS, XRCE-DDS, Zenoh) que apoia "
    "pesquisa academica em laboratorio controlado. A partir de uma vulnerabilidade ou "
    "descricao textual, voce produz uma analise estruturada para gerar cenarios de teste "
    "seguros. Responda SEMPRE com um unico objeto JSON valido, sem texto extra, sem markdown."
)

JSON_INSTRUCTIONS = """Retorne um JSON com exatamente estes campos:
{
  "protocol": "DDS | XRCE-DDS | Zenoh | <outro>",
  "likely_attack_type": "flooding | replay | malformed_message | oversized_payload | injection_simulated | unknown",
  "preconditions": "condicoes necessarias para reproduzir em lab",
  "expected_network_behavior": "o que se observa na rede durante o ataque",
  "dataset_label": "rotulo curto para o dataset, ex. xrce_dds_flooding",
  "confidence": 0.0,
  "safety_notes": "observacoes de seguranca; uso restrito a laboratorio controlado"
}"""


def build_user_prompt(text: str, protocol_hint: str | None) -> str:
    hint = f"\nProtocolo sugerido pelo usuario: {protocol_hint}" if protocol_hint else ""
    return (
        f"Vulnerabilidade/descricao:\n{text}{hint}\n\n{JSON_INSTRUCTIONS}\n"
        "Lembre-se: apenas o JSON."
    )
