"""Protocolos IoT plugaveis (XRCE-DDS, Zenoh, DDS, e extensoes).

Acoplar um novo protocolo: herde de `base.ProtocolPlugin`, implemente baseline_message
e health_probe, e chame `registry.register(SeuPlugin())`.
"""

from . import registry

registry.load_builtin()

__all__ = ["registry"]
