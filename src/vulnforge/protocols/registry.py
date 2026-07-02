from __future__ import annotations

import re

from .base import ProtocolPlugin

_plugins: dict[str, ProtocolPlugin] = {}
_loaded = False


def normalize(name: str) -> str:
    return re.sub(r"[_\s]+", "-", name.strip().lower())


def register(plugin: ProtocolPlugin) -> None:
    _plugins[normalize(plugin.name)] = plugin


def get(name: str) -> ProtocolPlugin | None:
    load_builtin()
    return _plugins.get(normalize(name))


def available() -> list[ProtocolPlugin]:
    load_builtin()
    return list(_plugins.values())


def load_builtin() -> None:
    global _loaded
    if _loaded:
        return
    from .dds import DdsPlugin
    from .xrce_dds import XrceDdsPlugin
    from .zenoh import ZenohPlugin
    for plugin in (XrceDdsPlugin(), ZenohPlugin(), DdsPlugin()):
        register(plugin)
    _loaded = True

