"""Structured logging utilities."""

from __future__ import annotations

import logging
from typing import Any


def setup_logging(level: str | int = "INFO") -> None:
    """Configure root logger with a consistent format."""
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_logger(name: str) -> logging.Logger:
    """Return a logger instance for the given module name."""
    return logging.getLogger(name)
