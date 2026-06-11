"""Wrapper para extracao de flows a partir de PCAP via CICFlowMeter.

Se a CLI `cicflowmeter` nao estiver instalada, registra a instrucao de instalacao
em vez de falhar silenciosamente.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..logging_setup import get_logger

log = get_logger(__name__)

INSTALL_HINT = (
    "CICFlowMeter nao encontrado. Instale a versao Python com:\n"
    "  pip install cicflowmeter\n"
    "e gere os flows manualmente com:\n"
    "  cicflowmeter -f <arquivo.pcap> -c <saida.csv>\n"
    "Depois rode: protoforge build-dataset --flows <saida.csv> --label <label> --out <dest.csv>"
)


def is_available() -> bool:
    return shutil.which("cicflowmeter") is not None


def extract_flows(pcap_path: str | Path, out_csv: str | Path) -> Path:
    """Extrai flows do PCAP para CSV. Levanta RuntimeError com instrucao se ausente."""
    if not is_available():
        log.warning(INSTALL_HINT)
        raise RuntimeError(INSTALL_HINT)

    out = Path(out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    log.info("Extraindo flows de %s -> %s", pcap_path, out)
    subprocess.run(
        ["cicflowmeter", "-f", str(pcap_path), "-c", str(out)],
        check=True,
    )
    return out
