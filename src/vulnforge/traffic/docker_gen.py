"""Gera Dockerfiles que empacotam os ataques nativos Python do VulnForge.

Segue o padrao do repo `ataques/` (ENTRYPOINT recebe <TARGET> <PORT>).
"""

from __future__ import annotations

from pathlib import Path

from ..traffic.attacks import common  # noqa: F401 - garante que o pacote existe

ATTACK_TYPES = ["flooding", "replay", "fuzz", "oversized", "malformed"]

_DOCKERFILE_TPL = """# Gerado por VulnForge AI - ataque nativo: {attack}
# Uso APENAS em laboratorio isolado. Alvo deve ser IP privado/loopback.
FROM python:3.11-slim
RUN pip install --no-cache-dir scapy
WORKDIR /opt/vulnforge
COPY src/vulnforge /opt/vulnforge/vulnforge
ENV PYTHONPATH=/opt/vulnforge
COPY {entrypoint_name} /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
"""

_ENTRYPOINT_TPL = """#!/usr/bin/env bash
# entrypoint do ataque nativo '{attack}': <TARGET> <PORT> [TRANSPORT] [DURATION]
set -e
TARGET="${{1:?uso: <TARGET> <PORT> [transport] [duration]}}"
PORT="${{2:?uso: <TARGET> <PORT> [transport] [duration]}}"
TRANSPORT="${{3:-udp}}"
DURATION="${{4:-15}}"
exec python -m vulnforge.traffic.attacks.{attack} \\
  --target "${{TARGET}}" --port "${{PORT}}" \\
  --transport "${{TRANSPORT}}" --duration "${{DURATION}}"
"""


def generate_dockerfile(attack: str, out_dir: str | Path) -> Path:
    """Gera Dockerfile + entrypoint para um tipo de ataque. Retorna o dir."""
    if attack not in ATTACK_TYPES:
        raise ValueError(f"Ataque desconhecido: {attack}. Opcoes: {', '.join(ATTACK_TYPES)}")
    out = Path(out_dir) / attack
    out.mkdir(parents=True, exist_ok=True)

    entrypoint_name = "entrypoint.sh"
    (out / "Dockerfile").write_text(
        _DOCKERFILE_TPL.format(attack=attack, entrypoint_name=entrypoint_name),
        encoding="utf-8",
    )
    (out / entrypoint_name).write_text(
        _ENTRYPOINT_TPL.format(attack=attack), encoding="utf-8"
    )
    readme = (
        f"# Ataque nativo VulnForge: {attack}\n\n"
        f"Build (a partir da raiz do repo vulnforge-ai):\n\n"
        f"    docker build -t vulnforge-attack-{attack} -f docker/attacks/{attack}/Dockerfile .\n\n"
        f"Executar (alvo deve ser IP privado/loopback):\n\n"
        f"    docker run --rm vulnforge-attack-{attack} 172.17.0.2 8888 udp 15\n\n"
        "Uso exclusivamente em laboratorio controlado.\n"
    )
    (out / "README.md").write_text(readme, encoding="utf-8")
    return out


# --- Bundle Docker para ATAQUE SINTETIZADO a partir de um CVE/cenario ---

# Imagens-alvo do repo `ataques/` por protocolo (servico 'target' no compose).
_TARGET_IMAGES: dict[str, dict] = {
    "XRCE-DDS": {
        "image": "iotedu-attack-xrce-dds-agent:latest",
        "command": '["udp4", "-p", "8888"]',
        "port": "8888/udp",
    },
    "Zenoh": {
        "image": "iotedu-attack-zenoh-router:latest",
        "command": "",
        "port": "7447",
    },
}

_SYNTH_DOCKERFILE_TPL = """# Gerado por VulnForge AI - ataque SINTETIZADO: {scenario_id}
# Protocolo {protocol} | estrategia {strategy} | fonte da sintese: {source}
# Uso APENAS em laboratorio isolado. Alvo deve ser IP privado/loopback.
# Build a partir da RAIZ do repo vulnforge-ai:
#   docker build -t vulnforge-synth-{scenario_id} -f docker/attacks/{scenario_id}/Dockerfile .
FROM python:3.11-slim
WORKDIR /opt/vulnforge
COPY src/vulnforge /opt/vulnforge/vulnforge
ENV PYTHONPATH=/opt/vulnforge
COPY docker/attacks/{scenario_id}/attack.py /opt/vulnforge/attack.py
COPY docker/attacks/{scenario_id}/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
"""

_SYNTH_ENTRYPOINT_TPL = """#!/usr/bin/env bash
# Ataque sintetizado '{scenario_id}'. Uso: <TARGET> [PORT] [DURATION]
set -e
TARGET="${{1:?uso: <TARGET> [port] [duration]}}"
PORT="${{2:-{port}}}"
DURATION="${{3:-{duration}}}"
exec python /opt/vulnforge/attack.py \\
  --target "${{TARGET}}" --port "${{PORT}}" \\
  --transport "{transport}" --duration "${{DURATION}}"
"""


def _compose(scenario_id: str, protocol: str, port: int, transport: str) -> str:
    target = _TARGET_IMAGES.get(protocol)
    attacker = (
        f"  attacker:\n"
        f"    build:\n"
        f"      context: ../../..\n"
        f"      dockerfile: docker/attacks/{scenario_id}/Dockerfile\n"
        f"    image: vulnforge-synth-{scenario_id}\n"
    )
    if target:
        cmd = f"    command: {target['command']}\n" if target["command"] else ""
        # 'target' resolve para IP privado da rede bridge do compose -> passa na guarda.
        return (
            "# docker-compose gerado por VulnForge AI (atacante + alvo de laboratorio).\n"
            "# Suba o alvo a partir das imagens do repo ataques/ (build-images-servers.sh).\n"
            "services:\n"
            "  target:\n"
            f"    image: {target['image']}\n"
            f"{cmd}"
            f"    expose:\n      - \"{target['port']}\"\n"
            f"{attacker}"
            "    depends_on:\n      - target\n"
            f"    command: [\"target\", \"{port}\", \"15\"]\n"
        )
    return (
        "# docker-compose gerado por VulnForge AI.\n"
        f"# Protocolo {protocol} sem imagem-alvo conhecida: defina o servico 'target' manualmente.\n"
        "services:\n"
        f"{attacker}"
        "    # command: [\"<IP_PRIVADO_DO_ALVO>\", \"%d\", \"15\"]\n" % port
    )


def generate_synth_bundle(
    *, scenario_id: str, protocol: str, strategy: str, source: str,
    module_code: str, port: int, transport: str, duration: float,
    out_dir: str | Path,
) -> Path:
    """Escreve o bundle Docker de um ataque sintetizado (Dockerfile, entrypoint, compose)."""
    out = Path(out_dir) / scenario_id
    out.mkdir(parents=True, exist_ok=True)

    (out / "attack.py").write_text(module_code, encoding="utf-8")
    (out / "Dockerfile").write_text(
        _SYNTH_DOCKERFILE_TPL.format(
            scenario_id=scenario_id, protocol=protocol, strategy=strategy, source=source,
        ),
        encoding="utf-8",
    )
    (out / "entrypoint.sh").write_text(
        _SYNTH_ENTRYPOINT_TPL.format(
            scenario_id=scenario_id, port=port, duration=int(duration), transport=transport,
        ),
        encoding="utf-8",
    )
    (out / "docker-compose.yml").write_text(
        _compose(scenario_id, protocol, port, transport), encoding="utf-8"
    )
    (out / "README.md").write_text(
        f"# Ataque sintetizado: {scenario_id}\n\n"
        f"- Protocolo: {protocol}\n- Estrategia: {strategy}\n- Fonte da sintese: {source}\n\n"
        "## Build & run isolado\n\n"
        f"    docker build -t vulnforge-synth-{scenario_id} -f docker/attacks/{scenario_id}/Dockerfile .\n"
        f"    docker run --rm vulnforge-synth-{scenario_id} 172.17.0.2 {port} 15\n\n"
        "## Atacante + alvo (compose)\n\n"
        "    docker compose -f docker/attacks/{0}/docker-compose.yml up --build\n\n".format(scenario_id)
        + "Uso EXCLUSIVO em laboratorio isolado. O alvo deve ser IP privado/loopback.\n",
        encoding="utf-8",
    )
    return out
