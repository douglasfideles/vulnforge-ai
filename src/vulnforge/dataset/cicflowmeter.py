"""Wrapper for the optional CICFlowMeter CLI."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from ..logging_setup import get_logger

logger = get_logger(__name__)


class CICFlowMeterError(RuntimeError):
    """Raised when CICFlowMeter is unavailable or fails."""


def find_cicflowmeter() -> str:
    path = shutil.which("cicflowmeter")
    if path:
        return path
    raise CICFlowMeterError(
        "cicflowmeter nao encontrado no PATH. "
        "Instale via: pip install cicflowmeter"
    )


def pcap_to_csv(pcap_path: str | Path, out_csv: str | Path | None = None) -> Path:
    """Convert a PCAP file to a flows CSV using cicflowmeter."""
    pcap = Path(pcap_path)
    if not pcap.exists():
        raise CICFlowMeterError(f"PCAP nao encontrado: {pcap}")

    if out_csv is None:
        out_csv = pcap.with_suffix(".flows.csv")
    out = Path(out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)

    cicflowmeter = find_cicflowmeter()
    cmd = [cicflowmeter, "-f", str(pcap), "-c", str(out)]
    logger.info("Executando: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise CICFlowMeterError(
            f"cicflowmeter falhou (rc={result.returncode}): {result.stderr}"
        )
    if not out.exists():
        raise CICFlowMeterError("cicflowmeter nao gerou o arquivo CSV de saida")
    return out
