"""Safety guard: restrict attack targets to lab networks."""

from __future__ import annotations

import ipaddress
import socket


class UnsafeTargetError(ValueError):
    """Raised when a target is outside the allowed lab ranges."""


ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
]


def _is_allowed_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for network in ALLOWED_NETWORKS:
        if addr in network:
            return True
    return False


def validate_target(target: str) -> str:
    """Resolve hostname and ensure target is loopback/private/link-local."""
    target = target.strip()
    if not target:
        raise UnsafeTargetError("Alvo vazio.")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"Nao foi possivel resolver o alvo: {target}") from exc
    if not _is_allowed_ip(ip):
        raise UnsafeTargetError(
            f"Alvo '{target}' ({ip}) nao e permitido. "
            "Use apenas 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 ou link-local."
        )
    return ip
