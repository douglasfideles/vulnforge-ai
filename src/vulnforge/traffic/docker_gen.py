"""Generate Dockerfiles and Docker bundles for native attacks."""

from __future__ import annotations

from pathlib import Path

ATTACK_TYPES = ["flooding", "replay", "fuzz", "oversized", "malformed"]


DOCKERFILE_TEMPLATE = """FROM python:3.11-slim

WORKDIR /app

# Install runtime deps
RUN pip install --no-cache-dir "typer>=0.12" "pydantic>=2.6" "PyYAML>=6.0"

COPY vulnforge/ /app/vulnforge/
ENV PYTHONPATH=/app

ENTRYPOINT ["python", "-m", "vulnforge.traffic.attacks.{attack}"]
"""


ENTRYPOINT_TEMPLATE = """#!/bin/sh
exec python -m vulnforge.traffic.attacks.{attack} "$@"
"""


COMPOSE_TEMPLATE = """services:
  {attack}:
    build: .
    network_mode: host
    command: ["--target", "127.0.0.1", "--port", "8888", "--transport", "udp"]
"""


def generate_dockerfile(attack_type: str, out_dir: str | Path) -> Path:
    """Generate a standalone Dockerfile for a native attack module."""
    out = Path(out_dir) / f"Dockerfile.{attack_type}"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(DOCKERFILE_TEMPLATE.format(attack=attack_type), encoding="utf-8")
    return out


def generate_bundle(scenario_id: str, attack_type: str, out_dir: str | Path) -> Path:
    """Generate a Docker bundle (Dockerfile + entrypoint + compose) for a scenario."""
    base = Path(out_dir) / scenario_id
    base.mkdir(parents=True, exist_ok=True)
    (base / "Dockerfile").write_text(DOCKERFILE_TEMPLATE.format(attack=attack_type), encoding="utf-8")
    (base / "entrypoint.sh").write_text(ENTRYPOINT_TEMPLATE.format(attack=attack_type), encoding="utf-8")
    (base / "docker-compose.yml").write_text(COMPOSE_TEMPLATE.format(attack=attack_type), encoding="utf-8")
    return base
