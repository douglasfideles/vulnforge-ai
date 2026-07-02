"""Tests for IDS trainer."""

import pandas as pd

from vulnforge.ids.trainer import train


def test_train_sample_dataset(tmp_path):
    path = tmp_path / "data.csv"
    rows = []
    for i in range(60):
        rows.append([i * 0.01, i * 0.02, i * 0.03, "normal"])
    for i in range(60):
        rows.append([1.0 + i * 0.01, 2.0 + i * 0.02, 3.0 + i * 0.03, "flooding"])
    df = pd.DataFrame(rows, columns=["f1", "f2", "f3", "label"])
    df.to_csv(path, index=False)
    result = train(path, test_size=0.3)
    assert result.rows == 120
    assert result.best_model in {"RandomForest", "LogisticRegression"}
    assert result.model_path.exists()
    assert result.report_path.exists()
    metrics = {m.name: m.f1 for m in result.metrics}
    assert metrics["RandomForest"] >= 0.99
    assert metrics["LogisticRegression"] >= 0.99
