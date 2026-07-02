"""Scenario YAML (de)serialization with readable validation errors."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from ..models import Scenario


class ScenarioValidationError(ValueError):
    """Readable validation error for scenario YAML."""

    def __init__(self, errors: list[dict]) -> None:
        messages = []
        for error in errors:
            loc = ".".join(str(item) for item in error.get("loc", []))
            msg = error.get("msg", "erro desconhecido")
            messages.append(f"{loc}: {msg}")
        super().__init__("Cenario invalido: " + "; ".join(messages))
        self.errors = errors


def load_scenario(path: str | Path) -> Scenario:
    path = Path(path)
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ScenarioValidationError([{"loc": ["root"], "msg": "YAML deve ser um mapeamento"}])
    try:
        return Scenario(**data)
    except ValidationError as exc:
        raise ScenarioValidationError(exc.errors()) from exc


def dump_scenario(scenario: Scenario, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = scenario.model_dump(mode="json")
    text = yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )
    path.write_text(text, encoding="utf-8")
    return path
