from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from vulnforge.config import get_settings


def train(dataset: str | Path, label_column: str = "label", test_size: float = 0.3) -> dict:
    dataset = Path(dataset)
    frame = pd.read_csv(dataset)
    if label_column not in frame:
        raise ValueError(f"Label column {label_column!r} is missing")
    features = frame.drop(columns=[label_column]).select_dtypes(include="number").columns.tolist()
    if not features:
        raise ValueError("Dataset has no numeric feature columns")
    x = frame[features].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y = frame[label_column].astype(str)
    classes = sorted(y.unique())
    if len(classes) < 2:
        raise ValueError("IDS training requires at least two distinct labels")
    stratify = y if y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=test_size, random_state=42, stratify=stratify
    )
    averaging = "binary" if len(classes) == 2 else "macro"
    metric_args = {"average": averaging, "zero_division": 0}
    if averaging == "binary":
        metric_args["pos_label"] = classes[-1]
    scaler = StandardScaler().fit(x_train)
    candidates = [
        ("RandomForest", RandomForestClassifier(n_estimators=100, random_state=42), x_train, x_test, None),
        ("LogisticRegression", LogisticRegression(max_iter=1000, random_state=42), scaler.transform(x_train), scaler.transform(x_test), scaler),
    ]
    results = []
    fitted = {}
    for name, model, train_x, test_x, fitted_scaler in candidates:
        model.fit(train_x, y_train)
        prediction = model.predict(test_x)
        results.append({
            "model": name, "accuracy": accuracy_score(y_test, prediction),
            "precision": precision_score(y_test, prediction, **metric_args),
            "recall": recall_score(y_test, prediction, **metric_args),
            "f1": f1_score(y_test, prediction, **metric_args),
            "confusion_matrix": confusion_matrix(y_test, prediction, labels=classes).tolist(),
        })
        fitted[name] = (model, fitted_scaler)
    # Stable tie-break deliberately favors RandomForest, the first baseline.
    best = max(results, key=lambda result: result["f1"])
    model, best_scaler = fitted[best["model"]]
    out_dir = get_settings().models_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / f"{dataset.stem}_{best['model']}.joblib"
    bundle = {"model": model, "features": features}
    if best_scaler is not None:
        bundle["scaler"] = best_scaler
    joblib.dump(bundle, model_path)
    report_path = out_dir / f"{dataset.stem}_ids_report.md"
    lines = [
        "# IDS Baseline Report", "", f"- Dataset: `{dataset}`", f"- Rows: {len(frame)}",
        f"- Classes: {', '.join(classes)}", f"- Features: {', '.join(features)}",
        f"- Best model: **{best['model']}**", "", "| Model | Accuracy | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|",
    ]
    for result in results:
        lines.append(f"| {result['model']} | {result['accuracy']:.4f} | {result['precision']:.4f} | {result['recall']:.4f} | {result['f1']:.4f} |")
    for result in results:
        lines.extend(["", f"## {result['model']} confusion matrix", "", "```", *(" ".join(map(str, row)) for row in result["confusion_matrix"]), "```"])
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "dataset": str(dataset), "rows": len(frame), "best_model": best["model"],
        "model_path": str(model_path), "report_path": str(report_path),
        "metrics": [{k: v for k, v in result.items() if k != "confusion_matrix"} for result in results],
    }

