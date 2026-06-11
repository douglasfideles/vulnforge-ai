"""Plugin XRCE-DDS (eProsima Micro XRCE-DDS Agent, UDP 8888).

Baseline: monta uma mensagem CREATE_CLIENT com o framing REAL do XRCE (cookie
'XRCE', versao, vendor eProsima, session header) - bem mais valido que bytes
aleatorios. A sonda envia essa mensagem e verifica se o agent responde.

A prova-de-fogo mais forte (uxr_ping via Micro-XRCE-DDS-Client em C) esta nos
containers do repo ataques/; aqui usamos a sonda de transporte protocol-aware.
"""

from __future__ import annotations

import socket
import time

from ..models import ProbeResult
from ..traffic.safety import assert_safe
from .base import ProtocolPlugin

# Constantes reais do protocolo XRCE-DDS.
_XRCE_COOKIE = bytes([0x58, 0x52, 0x43, 0x45])  # 'XRCE'
_XRCE_VERSION = bytes([0x01, 0x00])             # 1.0
_XRCE_VENDOR_EPROSIMA = bytes([0x01, 0x0F])
_SUBMSG_CREATE_CLIENT = 0x00
_FLAG_LITTLE_ENDIAN = 0x01


def _create_client_message(seq: int, client_key: bytes) -> bytes:
    """Monta um CREATE_CLIENT XRCE-DDS valido (best-effort, framing real)."""
    session_id = 0x81  # >= 0x80 => header sem client_key embutido (4 bytes)
    stream_id = 0x00
    seq_le = (seq & 0xFFFF).to_bytes(2, "little")
    session_header = bytes([session_id, stream_id]) + seq_le

    # ClientRepresentation (campos reais do XRCE).
    payload = (
        _XRCE_COOKIE + _XRCE_VERSION + _XRCE_VENDOR_EPROSIMA
        + client_key + bytes([session_id]) + bytes([0x00])  # properties: false
    )
    sub_len = len(payload).to_bytes(2, "little")
    submessage = bytes([_SUBMSG_CREATE_CLIENT, _FLAG_LITTLE_ENDIAN]) + sub_len + payload
    return session_header + submessage


class XrceDdsPlugin(ProtocolPlugin):
    name = "XRCE-DDS"
    default_port = 8888
    transport = "udp"
    target_image = "iotedu-attack-xrce-dds-agent:latest"
    install_hint = (
        "Para a prova mais forte (uxr_ping), use o Micro-XRCE-DDS-Client em C dos "
        "containers do repo ataques/. A sonda nativa nao requer dependencia extra."
    )

    def is_available(self) -> bool:
        return True  # baseline/sonda usam apenas stdlib (framing real embutido)

    def baseline_message(self, seq: int) -> bytes:
        return _create_client_message(seq, client_key=bytes([0xAA, 0xBB, 0xCC, 0xDD]))

    def health_probe(self, target: str, port: int | None = None) -> ProbeResult:
        assert_safe(target)
        port = port or self.default_port
        msg = self.baseline_message(0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        try:
            start = time.monotonic()
            sock.sendto(msg, (target, port))
            try:
                sock.recvfrom(4096)
                latency = (time.monotonic() - start) * 1000
                return ProbeResult(
                    responsive=True, latency_ms=latency, source="plugin",
                    detail="Agent XRCE-DDS respondeu ao CREATE_CLIENT.",
                )
            except socket.timeout:
                # UDP: ausencia de resposta nao prova queda -> inconclusivo.
                return ProbeResult(
                    responsive=False, source="plugin",
                    detail="Sem resposta ao CREATE_CLIENT em 1.5s (UDP: pode ser inconclusivo).",
                )
        except OSError as exc:
            return ProbeResult(responsive=False, source="plugin", detail=f"Erro de socket: {exc}")
        finally:
            sock.close()
