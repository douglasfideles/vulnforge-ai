"""Base protocol plugin and dependency error."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from ..models import ProbeResult


class ProtocolDependencyError(RuntimeError):
    """Raised when a protocol dependency is required but unavailable."""

    def __init__(self, message: str, install_hint: str = "") -> None:
        super().__init__(message)
        self.install_hint = install_hint


class ProtocolPlugin(ABC):
    """Abstract base class for DDS/XRCE-DDS/Zenoh plugins."""

    name: ClassVar[str] = ""
    default_port: ClassVar[int] = 0
    transport: ClassVar[str] = "udp"  # udp | tcp
    target_image: ClassVar[str | None] = None
    install_hint: ClassVar[str] = ""

    @classmethod
    def is_available(cls) -> bool:
        """Return True if optional protocol libraries are installed."""
        return True

    @classmethod
    def require(cls) -> None:
        """Raise ProtocolDependencyError if the plugin is unavailable."""
        if not cls.is_available():
            raise ProtocolDependencyError(
                f"Protocolo {cls.name} requer biblioteca adicional.",
                install_hint=cls.install_hint,
            )

    @abstractmethod
    def baseline_message(self, seq: int) -> bytes:
        """Return a valid protocol message payload for the given sequence number."""

    @abstractmethod
    def health_probe(self, target: str, port: int | None = None) -> ProbeResult:
        """Probe target responsiveness; degrade gracefully if libs are missing."""

    def capture_filter(self, port: int | None = None) -> str:
        p = port if port is not None else self.default_port
        return f"{self.transport} port {p}"


def identity_mutator(baseline: bytes, seq: int, rng: object) -> bytes:
    """Neutral mutator used for benign baseline traffic."""
    return baseline
