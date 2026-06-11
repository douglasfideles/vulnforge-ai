"""Guarda de seguranca: restringe ataques a alvos de laboratorio (IP privado/loopback)."""

from __future__ import annotations

import ipaddress
import socket


class UnsafeTargetError(RuntimeError):
    """Levantada quando o alvo nao e um IP de laboratorio permitido."""


def _resolve(host: str) -> str | None:
    """Resolve hostname para IP; retorna None se nao resolver."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError):
        return None


def is_private_target(target: str) -> bool:
    """True se o alvo for loopback/privado/link-local (seguro para lab)."""
    if not target:
        return False
    candidate = target.strip()
    ip_str = candidate
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        resolved = _resolve(candidate)
        if resolved is None:
            return False
        ip_str = resolved
    ip = ipaddress.ip_address(ip_str)
    return ip.is_private or ip.is_loopback or ip.is_link_local


def assert_safe(target: str) -> None:
    """Levanta UnsafeTargetError se o alvo nao for de laboratorio."""
    if not is_private_target(target):
        raise UnsafeTargetError(
            f"Alvo '{target}' nao e um IP privado/loopback. "
            "Por seguranca, ataques so podem rodar contra alvos de laboratorio "
            "(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, link-local). "
            "Ajuste o --target do cenario."
        )


def extract_target(command: str) -> str | None:
    """Extrai o valor de --target de um comando, se houver."""
    parts = command.split()
    for i, tok in enumerate(parts):
        if tok == "--target" and i + 1 < len(parts):
            return parts[i + 1]
    return None
