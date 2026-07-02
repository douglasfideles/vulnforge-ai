"""Zenoh protocol plugin."""

from __future__ import annotations

import socket
from typing import ClassVar

from ..models import ProbeResult
from .base import ProtocolPlugin


class ZenohPlugin(ProtocolPlugin):
    """Eclipse Zenoh protocol plugin; default TCP 7447."""

    name = "Zenoh"
    default_port = 7447
    transport = "tcp"
    target_image = "iotedu-attack-zenoh-router:latest"
    install_hint = "pip install 'vulnforge-ai[zenoh]' for eclipse-zenoh support."

    @classmethod
    def is_available(cls) -> bool:
        try:
            import zenoh  # type: ignore[import-not-found]
            return True
        except ImportError:
            return False

    def baseline_message(self, seq: int) -> bytes:
        # Zenoh protocol frame: scout message (transport-scout / 0x01).
        # Minimal frame header when no strong session is available.
        # Flags: 0x00 (default), frame type: 0x01 (scout).
        return b"\x00\x01" + seq.to_bytes(2, "big") + b"\x00"

    def health_probe(self, target: str, port: int | None = None) -> ProbeResult:
        if self.is_available():
            try:
                import zenoh  # type: ignore[import-not-found]
                config = zenoh.Config()
                config.insert_json5("mode", '"client"')
                config.insert_json5("connect", f'{{"endpoints": ["tcp/{target}:{port or self.default_port}"]}}')
                with zenoh.open(config) as session:
                    info = session.info()
                    return ProbeResult(
                        responsive=True,
                        detail=f"Zenoh session OK: {info}",
                        source="plugin",
                    )
            except Exception as exc:  # noqa: BLE001
                return ProbeResult(
                    responsive=False,
                    detail=f"Falha na sessao Zenoh: {exc}",
                    source="plugin",
                )
        p = port if port is not None else self.default_port
        try:
            with socket.create_connection((target, p), timeout=2.0):
                return ProbeResult(
                    responsive=True,
                    detail="Conexao TCP estabelecida",
                    source="tcp",
                )
        except OSError as exc:
            return ProbeResult(
                responsive=False,
                detail=f"Erro TCP: {exc}",
                source="tcp",
            )
