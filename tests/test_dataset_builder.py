"""Testes do dataset builder."""

import json

import pandas as pd
import pytest

from vulnforge.dataset.builder import build_dataset, merge_datasets


def _make_flows(path):
    pd.DataFrame(
        {"f1": [1, 2, 3], "f2": [0.1, 0.2, 0.3]}
    ).to_csv(path, index=False)


def test_build_adds_label_column(tmp_path):
    src = tmp_path / "flows.csv"
    out = tmp_path / "ds.csv"
    _make_flows(src)

    meta = build_dataset(src, "flooding", out)

    df = pd.read_csv(out)
    assert "label" in df.columns
    assert (df["label"] == "flooding").all()
    assert meta.rows == 3
    assert meta.labels == ["flooding"]


def test_metadata_json_is_written(tmp_path):
    src = tmp_path / "flows.csv"
    out = tmp_path / "ds.csv"
    _make_flows(src)
    build_dataset(src, "normal", out)

    meta_path = out.with_suffix(out.suffix + ".meta.json")
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text())
    assert meta["rows"] == 3
    assert meta["label_column"] == "label"


def test_missing_input_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_dataset(tmp_path / "nope.csv", "x", tmp_path / "o.csv")


def test_unsupported_format_raises(tmp_path):
    bad = tmp_path / "data.txt"
    bad.write_text("oops")
    with pytest.raises(ValueError):
        build_dataset(bad, "x", tmp_path / "o.csv")


def test_merge_datasets(tmp_path):
    a = tmp_path / "a.csv"
    b = tmp_path / "b.csv"
    out = tmp_path / "m.csv"
    _make_flows(a)
    _make_flows(b)
    build_dataset(a, "normal", a)
    build_dataset(b, "flooding", b)

    meta = merge_datasets([a, b], out)
    assert meta.rows == 6
    assert set(meta.labels) == {"normal", "flooding"}
