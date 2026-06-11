"""Registro de plugins de protocolo (ponto de extensao)."""

from __future__ import annotations

from .base import ProtocolPlugin

_REGISTRY: dict[str, ProtocolPlugin] = {}


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(" ", "-")


def register(plugin: ProtocolPlugin) -> None:
    """Registra um plugin sob seu `name` normalizado."""
    _REGISTRY[_norm(plugin.name)] = plugin


def get(name: str) -> ProtocolPlugin | None:
    """Retorna o plugin do protocolo (case/sep-insensitive) ou None."""
    return _REGISTRY.get(_norm(name))


def available() -> dict[str, ProtocolPlugin]:
    """Mapa nome-normalizado -> plugin de todos os protocolos registrados."""
    return dict(_REGISTRY)


def load_builtin() -> None:
    """Registra os plugins embutidos. Idempotente."""
    from . import dds, xrce_dds, zenoh  # import tardio evita ciclos

    for plugin in (xrce_dds.XrceDdsPlugin(), zenoh.ZenohPlugin(), dds.DdsPlugin()):
        register(plugin)
