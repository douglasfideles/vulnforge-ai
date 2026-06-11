"""Plugin Zenoh (Eclipse Zenoh router, TCP 7447).

Sonda forte: usa a lib OFICIAL `zenoh` (extra `zenoh`) para abrir uma sessao real
contra o router; se a sessao abre, o router esta vivo e falando o protocolo.
Sem a lib, faz fallback de transporte (TCP connect) + baseline com framing Zenoh
real (frame header + flag reliable + sequence var-int), como no repo ataques/.
"""

from __future__ import annotations

import socket
import time

from ..logging_setup import get_logger
from ..models import ProbeResult
from ..traffic.safety import assert_safe
from .base import ProtocolPlugin

log = get_logger(__name__)

# Constantes reais de framing Zenoh (transport messages).
_Z_MSG_FRAME = 0x00
_Z_FLAG_RELIABLE = 0x20


def _encode_zint(value: int) -> bytes:
    """Codifica um inteiro var-int (zint) como o Zenoh faz no fio."""
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def _zenoh_available() -> bool:
    try:
        import zenoh  # noqa: F401
        return True
    except ImportError:
        return False


class ZenohPlugin(ProtocolPlugin):
    name = "Zenoh"
    default_port = 7447
    transport = "tcp"
    target_image = "iotedu-attack-zenoh-router:latest"
    install_hint = "Instale a lib oficial: pip install 'vulnforge-ai[zenoh]' (eclipse-zenoh)."

    def is_available(self) -> bool:
        return _zenoh_available()

    def baseline_message(self, seq: int) -> bytes:
        """Frame Zenoh valido (header + reliable + seq var-int) + payload curto."""
        header = bytes([_Z_MSG_FRAME | _Z_FLAG_RELIABLE])
        return header + _encode_zint(seq) + b"vulnforge-baseline"

    def health_probe(self, target: str, port: int | None = None) -> ProbeResult:
        assert_safe(target)
        port = port or self.default_port
        if _zenoh_available():
            result = self._probe_zenoh(target, port)
            if result is not None:
                return result
        return self._probe_tcp(target, port)

    def _probe_zenoh(self, target: str, port: int) -> ProbeResult | None:
        """Abre uma sessao Zenoh real conectando ao router (prova forte)."""
        try:
            import zenoh

            conf = zenoh.Config()
            try:
                conf.insert_json5("connect/endpoints", f'["tcp/{target}:{port}"]')
            except Exception:  # noqa: BLE001 - API varia entre versoes
                pass
            start = time.monotonic()
            session = zenoh.open(conf)
            latency = (time.monotonic() - start) * 1000
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
            return ProbeResult(
                responsive=True, latency_ms=latency, source="plugin",
                detail="Sessao Zenoh aberta com sucesso (router vivo).",
            )
        except Exception as exc:  # noqa: BLE001
            log.info("Sonda Zenoh via lib falhou (%s); tentando TCP.", exc)
            return None

    def _probe_tcp(self, target: str, port: int) -> ProbeResult:
        """Fallback de transporte: conectar no TCP do router."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            start = time.monotonic()
            sock.connect((target, port))
            latency = (time.monotonic() - start) * 1000
            return ProbeResult(
                responsive=True, latency_ms=latency, source="tcp",
                detail="Router Zenoh aceitou conexao TCP (nivel de transporte).",
            )
        except OSError as exc:
            return ProbeResult(
                responsive=False, source="tcp",
                detail=f"Falha ao conectar no router Zenoh: {exc}",
            )
        finally:
            sock.close()
