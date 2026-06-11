"""Interface plugavel de protocolo.

Um ProtocolPlugin encapsula o conhecimento REAL do protocolo (handshake, framing,
cliente legitimo, sonda de saude). E codigo CONFIAVEL e revisado - nao gerado por
LLM. A unica parte gerada por IA e o `mutator` (uma funcao sandboxed que transforma
uma mensagem-base valida em uma versao maliciosa).

Para acoplar um novo protocolo: herde de ProtocolPlugin, implemente os metodos e
registre com `registry.register(MeuPlugin())`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from ..models import ProbeResult

# Mutator: recebe (baseline_bytes, seq, rng) e devolve o payload a enviar.
Mutator = Callable[[bytes, int, "object"], bytes]


def identity_mutator(baseline: bytes, seq: int, rng) -> bytes:  # noqa: ANN001
    """Mutator neutro: envia a mensagem valida sem alteracao (ex.: flooding legitimo)."""
    return baseline


class ProtocolDependencyError(RuntimeError):
    """A lib real do protocolo nao esta instalada; instrucao de instalacao no texto."""


class ProtocolPlugin(ABC):
    """Contrato de um plugin de protocolo IoT."""

    name: str = "abstract"
    default_port: int = 0
    transport: str = "udp"            # udp | tcp
    target_image: str | None = None   # imagem docker do alvo de laboratorio (se houver)
    install_hint: str = ""            # como instalar a dep real, se ausente

    def is_available(self) -> bool:
        """True se a lib real do protocolo estiver disponivel para sessao valida."""
        return True

    @abstractmethod
    def baseline_message(self, seq: int) -> bytes:
        """Retorna os bytes de UMA mensagem VALIDA do protocolo (baseline legitimo).

        Usada como ponto de partida para o mutator e para gerar trafego normal.
        """

    @abstractmethod
    def health_probe(self, target: str, port: int | None = None) -> ProbeResult:
        """Sonda se o alvo ainda responde ao protocolo (antes/depois do ataque)."""

    def capture_filter(self, port: int | None = None) -> str:
        """Filtro BPF para a captura tcpdump (ajuda a isolar o trafego do protocolo)."""
        p = port or self.default_port
        return f"{self.transport} port {p}"

    def require(self) -> None:
        """Levanta ProtocolDependencyError com instrucao se a lib real faltar."""
        if not self.is_available():
            raise ProtocolDependencyError(
                f"Protocolo '{self.name}' requer dependencia real ausente. {self.install_hint}"
            )
