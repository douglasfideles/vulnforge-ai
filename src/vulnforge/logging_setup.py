"""Configuracao de logging reutilizavel."""

from __future__ import annotations

import logging

_configured = False


def setup_logging(level: str = "INFO") -> None:
    """Configura o root logger uma unica vez."""
    global _configured
    if _configured:
        return
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Retorna um logger nomeado, garantindo o setup."""
    setup_logging()
    return logging.getLogger(name)
