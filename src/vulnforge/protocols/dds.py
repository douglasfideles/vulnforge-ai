"""DDS (RTPS) protocol plugin."""

from __future__ import annotations

import socket
import struct
from typing import ClassVar

from ..models import ProbeResult
from .base import ProtocolPlugin


class DdsPlugin(ProtocolPlugin):
    """DDS/RTPS plugin; default UDP 7400."""

    name = "DDS"
    default_port = 7400
    transport = "udp"
    target_image = "iotedu-attack-dds-agent:latest"
    install_hint = "pip install 'vulnforge-ai[dds]' for cyclonedds support."

    @classmethod
    def is_available(cls) -> bool:
        try:
            import cyclonedds  # type: ignore[import-not-found]
            return True
        except ImportError:
            return False

    def baseline_message(self, seq: int) -> bytes:
        # RTPS header: magic "RTPS", protocol version 2.2, vendor eProsima 0x01 0x0F.
        header = b"RTPS" + struct.pack("<BB", 2, 2) + struct.pack("<BB", 0x01, 0x0F)
        # GUID prefix (12 bytes) derived from sequence.
        guid_prefix = struct.pack("<I", seq & 0xFFFFFFFF) + b"\x00" * 8
        # SPDP participant data submessage id 0x15, flags 0x07.
        payload = guid_prefix + b"\x00\x00\x10\x00" + b"\x00" * 16
        submessage_header = struct.pack("<BBH", 0x15, 0x07, len(payload))
        return header + submessage_header + payload

    def health_probe(self, target: str, port: int | None = None) -> ProbeResult:
        if self.is_available():
            try:
                import cyclonedds  # type: ignore[import-not-found]
                return ProbeResult(
                    responsive=True,
                    detail="cyclonedds disponivel (probe simplificado)",
                    source="plugin",
                )
            except Exception as exc:  # noqa: BLE001
                return ProbeResult(
                    responsive=False,
                    detail=f"Falha cyclonedds: {exc}",
                    source="plugin",
                )
        p = port if port is not None else self.default_port
        payload = self.baseline_message(0)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)
                sock.sendto(payload, (target, p))
                data, _ = sock.recvfrom(1024)
                return ProbeResult(
                    responsive=True,
                    detail=f"Resposta UDP RTPS {len(data)} bytes",
                    source="udp",
                )
        except socket.timeout:
            return ProbeResult(
                responsive=False,
                detail="Timeout na sonda UDP RTPS",
                source="udp",
            )
        except OSError as exc:
            return ProbeResult(
                responsive=False,
                detail=f"Erro de rede: {exc}",
                source="udp",
            )
