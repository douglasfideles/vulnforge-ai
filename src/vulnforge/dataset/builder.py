from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from vulnforge.models import DatasetMeta


def _flows(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)
    if path.suffix.lower() not in (".pcap", ".pcapng"):
        raise ValueError("Flow input must be .csv, .pcap, or .pcapng")
    executable = shutil.which("cicflowmeter")
    if not executable:
        raise RuntimeError("CICFlowMeter is required for PCAP input; install cicflowmeter or provide an extracted flow CSV")
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "flows.csv"
        subprocess.run([executable, "-f", str(path), "-c", str(output)], check=True)
        return pd.read_csv(output)


def _write(frame: pd.DataFrame, source: Path, output: Path, label_column: str, notes: str = "") -> DatasetMeta:
    if frame.empty:
        raise ValueError("Cannot build a dataset from an empty flow set")
    output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)
    meta = DatasetMeta(
        name=output.stem, source_file=str(source), rows=len(frame), label_column=label_column,
        labels=sorted(frame[label_column].astype(str).unique().tolist()),
        created_at=datetime.now(timezone.utc).isoformat(), notes=notes,
    )
    Path(str(output) + ".meta.json").write_text(meta.model_dump_json(indent=2), encoding="utf-8")
    return meta


def build_dataset(source: str | Path, label: str, output: str | Path, label_column: str = "label") -> DatasetMeta:
    source, output = Path(source), Path(output)
    frame = _flows(source)
    frame[label_column] = label
    return _write(frame, source, output, label_column)


def merge_datasets(inputs: list[str | Path], output: str | Path, label_column: str = "label") -> DatasetMeta:
    frames = []
    for item in map(Path, inputs):
        frame = pd.read_csv(item)
        if label_column not in frame:
            frame = frame.rename(columns={frame.columns[-1]: label_column})
        frames.append(frame)
    return _write(pd.concat(frames, ignore_index=True), Path(",".join(map(str, inputs))), Path(output), label_column, "Merged labeled datasets")

