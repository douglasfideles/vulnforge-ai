"""XRCE-DDS protocol plugin."""

from __future__ import annotations

import socket
import struct
from typing import ClassVar

from ..models import ProbeResult
from .base import ProtocolPlugin


class XrceDdsPlugin(ProtocolPlugin):
    """Micro XRCE-DDS agent plugin; default UDP 8888."""

    name = "XRCE-DDS"
    default_port = 8888
    transport = "udp"
    target_image = "iotedu-attack-xrce-dds-agent:latest"
    install_hint = "pip install 'vulnforge-ai[dds]' or implement a manual agent."

    def baseline_message(self, seq: int) -> bytes:
        # XRCE CREATE_CLIENT_Payload / submessage header.
        # Cookie "XRCE", version 0x01 0x00, vendor eProsima 0x01 0x0F.
        header = b"XRCE" + struct.pack("<BB", 1, 0) + struct.pack("<BB", 0x01, 0x0F)
        # Submessage id 0x01 (CREATE_CLIENT), flags 0x07 (little-endian + inline qos),
        # octets-to-next-header calculated for payload.
        session_id = 0x80 | (seq & 0x7F)
        session_info = struct.pack("<BB", session_id, 0x00)
        stream_id = b"\x80"  # best-effort output stream
        seq_num = struct.pack("<H", seq & 0xFFFF)
        payload = session_info + stream_id + seq_num + b"\x00\x00\x00\x00"
        submessage_header = struct.pack("<BBH", 0x01, 0x07, len(payload))
        return header + submessage_header + payload

    def health_probe(self, target: str, port: int | None = None) -> ProbeResult:
        p = port if port is not None else self.default_port
        payload = self.baseline_message(0)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)
                sock.sendto(payload, (target, p))
                data, _ = sock.recvfrom(1024)
                return ProbeResult(
                    responsive=True,
                    detail=f"Resposta UDP {len(data)} bytes",
                    source="udp",
                )
        except socket.timeout:
            return ProbeResult(
                responsive=False,
                detail="Timeout na sonda UDP XRCE-DDS",
                source="udp",
            )
        except OSError as exc:
            return ProbeResult(
                responsive=False,
                detail=f"Erro de rede: {exc}",
                source="udp",
            )
