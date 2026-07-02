import json

import pandas as pd
import pytest

from vulnforge.dataset.builder import build_dataset, merge_datasets
from vulnforge.db import connect, get_analysis, get_run, get_vuln, save_analysis, save_run, upsert_vuln
from vulnforge.models import RunRecord, ThreatAnalysis, Vulnerability


def test_dataset_build_and_meta(tmp_path):
    source = tmp_path / "flows.csv"
    pd.DataFrame({"packets": [1, 2], "bytes": [10, 20]}).to_csv(source, index=False)
    output = tmp_path / "labeled.csv"
    meta = build_dataset(source, "normal", output)
    assert meta.rows == 2
    assert pd.read_csv(output)["label"].tolist() == ["normal", "normal"]
    assert json.loads((tmp_path / "labeled.csv.meta.json").read_text())["labels"] == ["normal"]


def test_dataset_empty_rejected(tmp_path):
    source = tmp_path / "empty.csv"
    source.write_text("packets,bytes\n")
    with pytest.raises(ValueError, match="empty"):
        build_dataset(source, "x", tmp_path / "out.csv")


def test_merge_datasets(tmp_path):
    one, two = tmp_path / "one.csv", tmp_path / "two.csv"
    pd.DataFrame({"x": [1], "label": ["a"]}).to_csv(one, index=False)
    pd.DataFrame({"x": [2], "label": ["b"]}).to_csv(two, index=False)
    meta = merge_datasets([one, two], tmp_path / "merged.csv")
    assert meta.rows == 2
    assert meta.labels == ["a", "b"]


def test_database_round_trip(tmp_path):
    conn = connect(tmp_path / "test.db")
    vuln = Vulnerability(id="CVE-1", title="first")
    upsert_vuln(vuln, conn)
    upsert_vuln(Vulnerability(id="CVE-1", title="updated"), conn)
    assert get_vuln("CVE-1", conn).title == "updated"
    analysis = ThreatAnalysis(protocol="DDS")
    save_analysis("CVE-1", analysis, conn)
    assert get_analysis("CVE-1", conn).protocol == "DDS"
    run = RunRecord(run_id="run-1", scenario_id="s", started_at="now", status="dry-run")
    save_run(run, "scenario_id: s", conn)
    assert get_run("run-1", conn)["status"] == "dry-run"
    conn.close()

