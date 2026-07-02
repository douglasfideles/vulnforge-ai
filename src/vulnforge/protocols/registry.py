"""Protocol plugin registry."""

from __future__ import annotations

from typing import TypeVar

from .base import ProtocolPlugin
from .dds import DdsPlugin
from .xrce_dds import XrceDdsPlugin
from .zenoh import ZenohPlugin

T = TypeVar("T", bound=ProtocolPlugin)

_REGISTRY: dict[str, type[ProtocolPlugin]] = {}


def _normalize_name(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(" ", "-")


def register(plugin_cls: type[T]) -> type[T]:
    """Register a protocol plugin under its normalized name."""
    key = _normalize_name(plugin_cls.name)
    _REGISTRY[key] = plugin_cls
    return plugin_cls


def get(name: str) -> type[ProtocolPlugin]:
    """Look up a plugin by normalized name; raise KeyError if missing."""
    key = _normalize_name(name)
    if key not in _REGISTRY:
        raise KeyError(f"Protocolo nao registrado: {name}")
    return _REGISTRY[key]


def available() -> dict[str, type[ProtocolPlugin]]:
    """Return a snapshot of registered plugins."""
    return dict(_REGISTRY)


def load_builtin() -> None:
    """Idempotently load built-in plugins."""
    for cls in (XrceDdsPlugin, ZenohPlugin, DdsPlugin):
        register(cls)


# Auto-load on import.
load_builtin()
