"""IDS baseline: treina RandomForest e LogisticRegression e gera metricas/relatorio."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ..config import get_settings
from ..logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class ModelResult:
    name: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    confusion: list[list[int]]
    labels: list[str]


@dataclass
class TrainResult:
    dataset: str
    rows: int
    features: list[str]
    label_column: str
    classes: list[str]
    results: list[ModelResult] = field(default_factory=list)
    best_model: str = ""
    model_path: str = ""
    report_path: str = ""


def _prepare_xy(df: pd.DataFrame, label_column: str):
    """Seleciona features numericas e separa rotulo. Trata NaN/inf."""
    if label_column not in df.columns:
        raise ValueError(f"Coluna de label '{label_column}' nao existe no dataset.")
    y = df[label_column].astype(str)
    features = df.drop(columns=[label_column]).select_dtypes(include="number")
    if features.empty:
        raise ValueError("Nenhuma feature numerica encontrada para treinar.")
    features = features.replace([float("inf"), float("-inf")], pd.NA).fillna(0.0)
    return features, y


def _evaluate(name, model, x_test, y_test) -> ModelResult:
    preds = model.predict(x_test)
    labels = sorted(set(y_test) | set(preds))
    avg = "binary" if len(labels) == 2 else "macro"
    pos = labels[-1] if avg == "binary" else None
    return ModelResult(
        name=name,
        accuracy=float(accuracy_score(y_test, preds)),
        precision=float(precision_score(y_test, preds, average=avg, pos_label=pos, zero_division=0)),
        recall=float(recall_score(y_test, preds, average=avg, pos_label=pos, zero_division=0)),
        f1=float(f1_score(y_test, preds, average=avg, pos_label=pos, zero_division=0)),
        confusion=confusion_matrix(y_test, preds, labels=labels).tolist(),
        labels=labels,
    )


def train(
    dataset_path: str | Path,
    label_column: str = "label",
    test_size: float = 0.3,
    out_dir: str | Path | None = None,
) -> TrainResult:
    """Treina RF + LogReg, escolhe o melhor por f1, salva .joblib e relatorio .md."""
    dataset_path = Path(dataset_path)
    df = pd.read_csv(dataset_path)
    x, y = _prepare_xy(df, label_column)

    settings = get_settings()
    out_dir = Path(out_dir) if out_dir else settings.models_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    stratify = y if y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=test_size, random_state=42, stratify=stratify
    )

    scaler = StandardScaler()
    x_train_s = scaler.fit_transform(x_train)
    x_test_s = scaler.transform(x_test)

    models = {
        "RandomForest": (RandomForestClassifier(n_estimators=100, random_state=42), x_train, x_test),
        "LogisticRegression": (
            LogisticRegression(max_iter=1000, random_state=42), x_train_s, x_test_s,
        ),
    }

    result = TrainResult(
        dataset=str(dataset_path),
        rows=int(len(df)),
        features=list(x.columns),
        label_column=label_column,
        classes=sorted(y.unique().tolist()),
    )

    fitted = {}
    for name, (model, xtr, xte) in models.items():
        model.fit(xtr, y_train)
        result.results.append(_evaluate(name, model, xte, y_test))
        fitted[name] = model

    best = max(result.results, key=lambda r: r.f1)
    result.best_model = best.name
    model_path = out_dir / f"{dataset_path.stem}_{best.name}.joblib"
    bundle = {"model": fitted[best.name], "features": result.features}
    if best.name == "LogisticRegression":
        bundle["scaler"] = scaler
    joblib.dump(bundle, model_path)
    result.model_path = str(model_path)

    report_path = out_dir / f"{dataset_path.stem}_ids_report.md"
    report_path.write_text(render_report(result), encoding="utf-8")
    result.report_path = str(report_path)

    log.info("IDS treinado. Melhor=%s f1=%.3f -> %s", best.name, best.f1, model_path)
    return result


def render_report(result: TrainResult) -> str:
    lines = [
        "# Relatorio IDS Baseline",
        "",
        f"- Dataset: `{result.dataset}`",
        f"- Linhas: {result.rows}",
        f"- Classes: {', '.join(result.classes)}",
        f"- Features ({len(result.features)}): {', '.join(result.features)}",
        f"- Melhor modelo: **{result.best_model}**",
        "",
        "## Metricas por modelo",
        "",
        "| Modelo | Accuracy | Precision | Recall | F1 |",
        "|--------|----------|-----------|--------|----|",
    ]
    for r in result.results:
        lines.append(
            f"| {r.name} | {r.accuracy:.3f} | {r.precision:.3f} | {r.recall:.3f} | {r.f1:.3f} |"
        )
    lines.append("")
    for r in result.results:
        lines.append(f"### Matriz de confusao - {r.name}")
        lines.append("")
        header = "| real \\ pred | " + " | ".join(r.labels) + " |"
        sep = "|" + "---|" * (len(r.labels) + 1)
        lines += [header, sep]
        for i, label in enumerate(r.labels):
            row = " | ".join(str(v) for v in r.confusion[i])
            lines.append(f"| {label} | {row} |")
        lines.append("")
    return "\n".join(lines)


def result_to_dict(result: TrainResult) -> dict:
    return {
        "dataset": result.dataset,
        "rows": result.rows,
        "best_model": result.best_model,
        "model_path": result.model_path,
        "report_path": result.report_path,
        "metrics": [
            {"model": r.name, "accuracy": r.accuracy, "precision": r.precision,
             "recall": r.recall, "f1": r.f1}
            for r in result.results
        ],
    }
