"""Validacao e (de)serializacao de cenarios YAML."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from ..models import Scenario


class ScenarioValidationError(ValueError):
    """Erro de validacao de cenario com mensagem clara."""


def validate_scenario(data: dict) -> Scenario:
    """Valida um dict em Scenario, levantando ScenarioValidationError legivel."""
    try:
        return Scenario(**data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ScenarioValidationError(f"Cenario invalido: {details}") from exc


def load_scenario(path: str | Path) -> Scenario:
    """Le e valida um cenario de um arquivo YAML."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Cenario nao encontrado: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ScenarioValidationError("O YAML do cenario deve ser um mapeamento (chave: valor).")
    return validate_scenario(data)


def dump_scenario(scenario: Scenario, path: str | Path) -> Path:
    """Serializa um Scenario em YAML legivel."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = scenario.model_dump(mode="json")
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return path
