"""Prompts for LLM-based threat analysis and exploit synthesis."""

from __future__ import annotations

ANALYSIS_SYSTEM_PROMPT = """You are a cybersecurity research assistant specialized in IoT pub/sub protocols (DDS, XRCE-DDS, Zenoh).
Analyze the vulnerability description and return ONLY a JSON object with these exact keys:
- protocol: one of XRCE-DDS, Zenoh, DDS, or unknown
- likely_attack_type: one of flooding, replay, malformed_message, oversized_payload, injection_simulated, normal, unknown
- preconditions: brief string
- expected_network_behavior: brief string
- dataset_label: suggested label like <protocol_slug>_<attack_type>
- confidence: float between 0.0 and 1.0
- safety_notes: brief ethical/lab safety note
Do not include any markdown formatting outside the JSON object.
"""


def analysis_user_prompt(text: str, protocol_hint: str | None = None) -> str:
    hint = f"\nProtocol hint: {protocol_hint}" if protocol_hint else ""
    return f"Vulnerability / threat description:\n{text}{hint}\n\nReturn JSON:"


SYNTHESIS_SYSTEM_PROMPT = """You are a cybersecurity research assistant that helps build controlled laboratory attacks for IoT pub/sub protocols.
You must produce ONLY a JSON object with these exact keys:
- strategy: short attack strategy name
- transport: udp or tcp
- port: integer port number
- rate: packets per second (int)
- duration: seconds (int)
- rationale: one sentence rationale
- mutator_code: a Python function body (no imports, no I/O) implementing mutate(baseline, seq, rng, urandom) -> bytes
The mutator body must:
  * return a non-empty bytes object
  * only use: bytes, bytearray, int, float, bool, len, range, min, max, abs, list, tuple, sum, ord, chr, bin, hex, reversed, enumerate
  * only rng methods: randrange, randint, random, getrandbits, choice, randbytes
  * not use imports, loops (for/while), attribute access besides rng.*, power (**), or integer constants > 1_000_000
  * not use open, exec, eval, print
Do not include markdown fences; return raw JSON only.
"""


def synthesis_user_prompt(text: str, analysis_json: str) -> str:
    return (
        f"Threat description:\n{text}\n\n"
        f"Threat analysis:\n{analysis_json}\n\n"
        "Synthesize the attack parameters and mutator code as JSON."
    )
