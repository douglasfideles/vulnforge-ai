"""Baseline IDS training: RandomForest + LogisticRegression."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ..logging_setup import get_logger

logger = get_logger(__name__)


@dataclass
class ModelResult:
    name: str
    model: object
    scaler: object | None
    accuracy: float
    precision: float
    recall: float
    f1: float
    confusion: list[list[int]]


@dataclass
class TrainResult:
    dataset: str
    rows: int
    best_model: str
    model_path: Path
    report_path: Path
    metrics: list[ModelResult]


def _numeric_features(df: pd.DataFrame, label_column: str) -> tuple[pd.DataFrame, list[str]]:
    feature_cols = [c for c in df.columns if c != label_column]
    numeric_cols = []
    for col in feature_cols:
        if pd.api.types.is_numeric_dtype(df[col]):
            numeric_cols.append(col)
    if not numeric_cols:
        raise ValueError("Nenhuma coluna numerica encontrada para treino")
    X = df[numeric_cols].copy()
    X.replace([float("inf"), float("-inf")], float("nan"), inplace=True)
    X.fillna(0.0, inplace=True)
    return X, numeric_cols


def _binary_labels(y: pd.Series) -> bool:
    return y.nunique() == 2


def _averaging(y: pd.Series) -> str:
    return "binary" if _binary_labels(y) else "macro"


def _positive_label(y: pd.Series) -> str:
    return sorted(y.unique())[-1]


def train(
    dataset_path: str | Path,
    label_column: str = "label",
    test_size: float = 0.3,
) -> TrainResult:
    path = Path(dataset_path)
    df = pd.read_csv(path)
    if label_column not in df.columns:
        raise ValueError(f"Coluna de rotulo '{label_column}' nao encontrada")

    X, feature_cols = _numeric_features(df, label_column)
    y = df[label_column]
    rows = len(df)

    stratify = y if _binary_labels(y) and y.value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=stratify
    )

    avg = _averaging(y)
    pos_label = _positive_label(y) if _binary_labels(y) else None

    results: list[ModelResult] = []

    # Random Forest
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    y_pred_rf = rf.predict(X_test)
    results.append(
        ModelResult(
            name="RandomForest",
            model=rf,
            scaler=None,
            accuracy=accuracy_score(y_test, y_pred_rf),
            precision=precision_score(y_test, y_pred_rf, average=avg, pos_label=pos_label),
            recall=recall_score(y_test, y_pred_rf, average=avg, pos_label=pos_label),
            f1=f1_score(y_test, y_pred_rf, average=avg, pos_label=pos_label),
            confusion=confusion_matrix(y_test, y_pred_rf).tolist(),
        )
    )

    # Logistic Regression with StandardScaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    lr = LogisticRegression(max_iter=1000, random_state=42, solver="lbfgs")
    lr.fit(X_train_scaled, y_train)
    y_pred_lr = lr.predict(X_test_scaled)
    results.append(
        ModelResult(
            name="LogisticRegression",
            model=lr,
            scaler=scaler,
            accuracy=accuracy_score(y_test, y_pred_lr),
            precision=precision_score(y_test, y_pred_lr, average=avg, pos_label=pos_label),
            recall=recall_score(y_test, y_pred_lr, average=avg, pos_label=pos_label),
            f1=f1_score(y_test, y_pred_lr, average=avg, pos_label=pos_label),
            confusion=confusion_matrix(y_test, y_pred_lr).tolist(),
        )
    )

    best = max(results, key=lambda r: r.f1)
    bundle = {"model": best.model, "features": feature_cols}
    if best.scaler is not None:
        bundle["scaler"] = best.scaler

    model_path = Path("data/models") / f"{path.stem}_{best.name}.joblib"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)

    report_path = Path("data/models") / f"{path.stem}_ids_report.md"
    report_path.write_text(_render_report(path, rows, feature_cols, results, best), encoding="utf-8")

    return TrainResult(
        dataset=str(path),
        rows=rows,
        best_model=best.name,
        model_path=model_path,
        report_path=report_path,
        metrics=results,
    )


def _render_report(
    path: Path,
    rows: int,
    feature_cols: list[str],
    results: list[ModelResult],
    best: ModelResult,
) -> str:
    lines = [
        "# VulnForge AI - IDS Baseline Training Report",
        "",
        f"**Dataset:** `{path}`",
        f"**Rows:** {rows}",
        f"**Features:** {len(feature_cols)}",
        f"**Best model:** {best.name} (F1 = {best.f1:.4f})",
        "",
        "## Features",
        "",
        "\n".join(f"- `{f}`" for f in feature_cols),
        "",
        "## Metrics",
        "",
        "| Model | Accuracy | Precision | Recall | F1 |",
        "|-------|----------|-----------|--------|----|",
    ]
    for r in results:
        lines.append(
            f"| {r.name} | {r.accuracy:.4f} | {r.precision:.4f} | {r.recall:.4f} | {r.f1:.4f} |"
        )
    for r in results:
        lines.extend([
            "",
            f"## Confusion Matrix - {r.name}",
            "",
            "```",
            str(r.confusion),
            "```",
        ])
    return "\n".join(lines) + "\n"


def result_to_dict(result: TrainResult) -> dict:
    return {
        "dataset": result.dataset,
        "rows": result.rows,
        "best_model": result.best_model,
        "model_path": str(result.model_path),
        "report_path": str(result.report_path),
        "metrics": [
            {
                "model": m.name,
                "accuracy": m.accuracy,
                "precision": m.precision,
                "recall": m.recall,
                "f1": m.f1,
            }
            for m in result.metrics
        ],
    }
