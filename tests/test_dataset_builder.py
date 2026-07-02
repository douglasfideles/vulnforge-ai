"""Tests for dataset builder."""

import pandas as pd
import pytest

from vulnforge.dataset.builder import build_dataset


def test_build_from_csv(tmp_path):
    flows = tmp_path / "flows.csv"
    flows.write_text("a,b\n1,2\n3,4\n")
    out = tmp_path / "out.csv"
    meta = build_dataset(flows, "attack", out)
    assert meta.rows == 2
    assert meta.labels == ["attack"]
    df = pd.read_csv(out)
    assert list(df["label"]) == ["attack", "attack"]


def test_empty_flows_error(tmp_path):
    flows = tmp_path / "flows.csv"
    flows.write_text("a,b\n")
    with pytest.raises(ValueError, match="vazio"):
        build_dataset(flows, "attack", tmp_path / "out.csv")
