"""Build labeled datasets from CSV flows or PCAP files."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from ..logging_setup import get_logger
from ..models import DatasetMeta
from .cicflowmeter import CICFlowMeterError, pcap_to_csv

logger = get_logger(__name__)


def build_dataset(
    source: str | Path,
    label: str,
    out: str | Path,
    label_column: str = "label",
) -> DatasetMeta:
    """Build a labeled dataset from CSV flows or PCAP/PCAPNG."""
    source_path = Path(source)
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    suffix = source_path.suffix.lower()
    if suffix in {".pcap", ".pcapng"}:
        flows_path = pcap_to_csv(source_path)
        df = pd.read_csv(flows_path)
    else:
        df = pd.read_csv(source_path)

    if df.empty:
        raise ValueError("Conjunto de flows vazio")

    df[label_column] = label
    df.to_csv(out_path, index=False)

    meta = DatasetMeta(
        name=out_path.stem,
        source_file=str(source_path),
        rows=len(df),
        label_column=label_column,
        labels=sorted(df[label_column].unique().tolist()),
        created_at=datetime.now(timezone.utc).isoformat(),
        notes=f"Label aplicado: {label}",
    )
    meta_path = out_path.with_suffix(out_path.suffix + ".meta.json")
    meta_path.write_text(json.dumps(meta.model_dump(mode="json"), indent=2), encoding="utf-8")
    return meta


def merge_datasets(csv_paths: list[str | Path], out: str | Path) -> DatasetMeta:
    """Merge multiple labeled CSVs into one multi-class dataset."""
    frames: list[pd.DataFrame] = []
    for path in csv_paths:
        df = pd.read_csv(path)
        if "label" not in df.columns:
            # Use last column as fallback label.
            df = df.copy()
            df["label"] = df.iloc[:, -1]
        frames.append(df)

    if not frames:
        raise ValueError("Nenhum CSV fornecido para merge")

    merged = pd.concat(frames, ignore_index=True)
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(out_path, index=False)

    meta = DatasetMeta(
        name=out_path.stem,
        source_file=", ".join(str(p) for p in csv_paths),
        rows=len(merged),
        label_column="label",
        labels=sorted(merged["label"].unique().tolist()),
        created_at=datetime.now(timezone.utc).isoformat(),
        notes="Dataset resultante de merge multi-classe",
    )
    meta_path = out_path.with_suffix(out_path.suffix + ".meta.json")
    meta_path.write_text(json.dumps(meta.model_dump(mode="json"), indent=2), encoding="utf-8")
    return meta
