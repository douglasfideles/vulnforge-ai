from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal

from vulnforge.models import ProbeResult


class ProtocolDependencyError(RuntimeError):
    pass


class ProtocolPlugin(ABC):
    name = "unknown"
    default_port = 0
    transport: Literal["udp", "tcp"] = "udp"
    target_image: str | None = None
    install_hint = ""

    def is_available(self) -> bool:
        return True

    @abstractmethod
    def baseline_message(self, seq: int) -> bytes: ...

    @abstractmethod
    def health_probe(self, target: str, port: int | None = None) -> ProbeResult: ...

    def capture_filter(self, port: int | None = None) -> str:
        return f"{self.transport} port {port or self.default_port}"

    def require(self) -> None:
        if not self.is_available():
            raise ProtocolDependencyError(self.install_hint or f"{self.name} dependency unavailable")

