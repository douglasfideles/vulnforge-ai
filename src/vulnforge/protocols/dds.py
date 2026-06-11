"""Plugin DDS / RTPS (Fast DDS / CycloneDDS, UDP 7400).

Sonda forte: usa `cyclonedds` (extra `dds`) para subir um DomainParticipant real e
confirmar que o stack DDS opera. Sem a lib, faz baseline com header RTPS real
(magic 'RTPS' + versao + vendorId + GuidPrefix) e sonda UDP send/listen.

Observacao: DDS e descentralizado (discovery via multicast SPDP); a sonda unicast
a 7400 e best-effort e pode ser inconclusiva - refletido no `detail`/verdict.
"""

from __future__ import annotations

import os
import socket
import time

from ..logging_setup import get_logger
from ..models import ProbeResult
from ..traffic.safety import assert_safe
from .base import ProtocolPlugin

log = get_logger(__name__)

# Header RTPS real.
_RTPS_MAGIC = bytes([0x52, 0x54, 0x50, 0x53])      # 'RTPS'
_RTPS_VERSION = bytes([0x02, 0x01])                # 2.1
_RTPS_VENDOR_EPROSIMA = bytes([0x01, 0x0F])
# Submessage INFO_TS (id 0x09) minimo, flags LE.
_SUBMSG_INFO_TS = 0x09
_FLAG_LE = 0x01


def _cyclonedds_available() -> bool:
    try:
        import cyclonedds  # noqa: F401
        return True
    except ImportError:
        return False


def _rtps_message(seq: int) -> bytes:
    """Monta uma mensagem RTPS valida (header real + submessage INFO_TS)."""
    guid_prefix = _RTPS_VENDOR_EPROSIMA + (seq & 0xFFFFFFFF).to_bytes(4, "little") + os.urandom(6)
    header = _RTPS_MAGIC + _RTPS_VERSION + _RTPS_VENDOR_EPROSIMA + guid_prefix
    # INFO_TS: submessageId, flags, octetsToNextHeader(2), timestamp(8)
    ts = int(time.time()).to_bytes(8, "little")
    submessage = bytes([_SUBMSG_INFO_TS, _FLAG_LE]) + (8).to_bytes(2, "little") + ts
    return header + submessage


class DdsPlugin(ProtocolPlugin):
    name = "DDS"
    default_port = 7400
    transport = "udp"
    target_image = None
    install_hint = "Instale o stack DDS: pip install 'vulnforge-ai[dds]' (cyclonedds)."

    def is_available(self) -> bool:
        return _cyclonedds_available()

    def baseline_message(self, seq: int) -> bytes:
        return _rtps_message(seq)

    def health_probe(self, target: str, port: int | None = None) -> ProbeResult:
        assert_safe(target)
        port = port or self.default_port
        if _cyclonedds_available():
            strong = self._probe_cyclone()
            if strong is not None:
                return strong
        return self._probe_udp(target, port)

    def _probe_cyclone(self) -> ProbeResult | None:
        """Sobe um DomainParticipant real (confirma que o stack DDS opera)."""
        try:
            from cyclonedds.domain import DomainParticipant

            start = time.monotonic()
            dp = DomainParticipant()
            latency = (time.monotonic() - start) * 1000
            del dp
            return ProbeResult(
                responsive=True, latency_ms=latency, source="plugin",
                detail="DomainParticipant DDS criado (stack RTPS operacional).",
            )
        except Exception as exc:  # noqa: BLE001
            log.info("Sonda DDS via cyclonedds falhou (%s); tentando UDP.", exc)
            return None

    def _probe_udp(self, target: str, port: int) -> ProbeResult:
        """Fallback: envia RTPS a 7400 e escuta resposta (best-effort)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        try:
            sock.sendto(_rtps_message(0), (target, port))
            try:
                sock.recvfrom(4096)
                return ProbeResult(
                    responsive=True, source="udp",
                    detail="Resposta RTPS recebida na porta DDS.",
                )
            except socket.timeout:
                return ProbeResult(
                    responsive=False, source="udp",
                    detail="Sem resposta RTPS em 1.5s (DDS usa discovery multicast: inconclusivo).",
                )
        except OSError as exc:
            return ProbeResult(responsive=False, source="udp", detail=f"Erro de socket: {exc}")
        finally:
            sock.close()
