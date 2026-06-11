"""Construcao de dataset rotulado a partir de PCAP ou CSV de flows."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from ..logging_setup import get_logger
from ..models import DatasetMeta
from . import cicflowmeter

log = get_logger(__name__)


def _load_flows(input_path: Path) -> pd.DataFrame:
    """Carrega flows de CSV; se PCAP, extrai via CICFlowMeter para um CSV temporario."""
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(input_path)
    if suffix in (".pcap", ".pcapng"):
        tmp_csv = input_path.with_suffix(".flows.csv")
        cicflowmeter.extract_flows(input_path, tmp_csv)
        return pd.read_csv(tmp_csv)
    raise ValueError(f"Formato nao suportado: {suffix}. Use .csv ou .pcap.")


def build_dataset(
    input_path: str | Path,
    label: str,
    out_path: str | Path,
    label_column: str = "label",
) -> DatasetMeta:
    """Le flows, adiciona/garante a coluna de label, salva CSV + metadata JSON.

    Retorna o DatasetMeta. Escreve `<out>.meta.json` ao lado do CSV.
    """
    input_path = Path(input_path)
    out_path = Path(out_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Entrada nao encontrada: {input_path}")

    df = _load_flows(input_path)
    if df.empty:
        raise ValueError("Nenhum flow encontrado na entrada.")

    df[label_column] = label
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    labels = sorted(df[label_column].astype(str).unique().tolist())
    meta = DatasetMeta(
        name=out_path.stem,
        source_file=str(input_path),
        rows=int(len(df)),
        label_column=label_column,
        labels=labels,
        created_at=datetime.now(timezone.utc).isoformat(),
        notes=f"Gerado de {input_path.name} com label fixo '{label}'.",
    )
    meta_path = out_path.with_suffix(out_path.suffix + ".meta.json")
    meta_path.write_text(json.dumps(meta.model_dump(), indent=2), encoding="utf-8")

    log.info("Dataset salvo: %s (%d linhas). Metadata: %s", out_path, meta.rows, meta_path)
    return meta


def merge_datasets(paths: list[str | Path], out_path: str | Path) -> DatasetMeta:
    """Concatena varios CSVs rotulados em um dataset unico (para treinar IDS multi-classe)."""
    frames = [pd.read_csv(p) for p in paths]
    df = pd.concat(frames, ignore_index=True)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    label_col = "label" if "label" in df.columns else df.columns[-1]
    meta = DatasetMeta(
        name=out_path.stem,
        source_file=",".join(str(p) for p in paths),
        rows=int(len(df)),
        label_column=label_col,
        labels=sorted(df[label_col].astype(str).unique().tolist()),
        created_at=datetime.now(timezone.utc).isoformat(),
        notes="Merge de datasets rotulados.",
    )
    out_path.with_suffix(out_path.suffix + ".meta.json").write_text(
        json.dumps(meta.model_dump(), indent=2), encoding="utf-8"
    )
    return meta
