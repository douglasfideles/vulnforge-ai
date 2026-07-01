#!/usr/bin/env python
"""Compara dataset gerado pela ferramenta VulnForge AI com o dataset real SBSeg 2024.

Carrega ambos os datasets, harmoniza para o schema canonico de 10 features,
calcula estatisticas e distancias de distribuicao (KS, Wasserstein, Jensen-Shannon),
e gera figuras + relatorio Markdown + metrics.json.

Requer: matplotlib, scipy  (pip install -r requirements-sbseg.txt)

Uso:
    python scripts/sbseg2024/compare_datasets.py
    python scripts/sbseg2024/compare_datasets.py \\
        --tool-dataset data/sbseg2024/tool/xrce_dds_tool.csv
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats
from scipy.spatial.distance import jensenshannon

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "scripts" / "sbseg2024"))
from harmonize import CANON_FEATURES, harmonize  # noqa: E402

REAL_DIR = REPO / "dataset-sbseg2024"
REPORTS_DIR = REPO / "reports" / "sbseg2024"
FIGS_DIR = REPORTS_DIR / "figs"
HARMONIZED_DIR = REPO / "data" / "sbseg2024" / "harmonized"

_PALETTE = {
    "real_aberta": "#26A69A",
    "real_isolada": "#1E5F74",
    "tool": "#EB9834",
}
_LABEL_COLORS = {"normal": "#279E60", "dos": "#C84646"}


# ------------------------------------------------------------------ loading

def _load_real(aberta: Path, isolada: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    df_a = pd.read_csv(aberta, low_memory=False)
    df_i = pd.read_csv(isolada, low_memory=False)
    return harmonize(df_a, "sbseg"), harmonize(df_i, "sbseg")


def _load_tool(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    return harmonize(df, "tool")


# ------------------------------------------------------------------ statistics

def _desc(s: pd.Series) -> dict:
    s = s.dropna()
    return {
        "mean": float(s.mean()) if len(s) else None,
        "std": float(s.std()) if len(s) else None,
        "median": float(s.median()) if len(s) else None,
        "p25": float(s.quantile(0.25)) if len(s) else None,
        "p75": float(s.quantile(0.75)) if len(s) else None,
        "n": int(len(s)),
    }


def _distances(a: pd.Series, b: pd.Series) -> dict:
    a, b = a.dropna(), b.dropna()
    if len(a) < 2 or len(b) < 2:
        return {"ks": None, "ks_p": None, "wasserstein": None, "js": None}
    ks_stat, ks_p = stats.ks_2samp(a, b)
    wass = float(stats.wasserstein_distance(a, b))
    lo = min(float(a.min()), float(b.min()))
    hi = max(float(a.max()), float(b.max()))
    if lo >= hi:
        return {"ks": float(ks_stat), "ks_p": float(ks_p), "wasserstein": wass, "js": 0.0}
    bins = np.linspace(lo, hi, 50)
    pa, _ = np.histogram(a, bins=bins, density=True)
    pb, _ = np.histogram(b, bins=bins, density=True)
    pa = (pa + 1e-10) / (pa + 1e-10).sum()
    pb = (pb + 1e-10) / (pb + 1e-10).sum()
    return {
        "ks": float(ks_stat),
        "ks_p": float(ks_p),
        "wasserstein": wass,
        "js": float(jensenshannon(pa, pb)),
    }


# ------------------------------------------------------------------ figures

def _hist(dfs: dict[str, pd.DataFrame], col: str, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(9, 5))
    for name, df in dfs.items():
        data = df[col].dropna()
        if len(data) == 0:
            continue
        lo, hi = data.quantile(0.01), data.quantile(0.99)
        data = data[(data >= lo) & (data <= hi)]
        ax.hist(data, bins=60, alpha=0.55, label=name,
                color=_PALETTE.get(name, "#888"), density=True)
    ax.set_title(f"Distribuicao: {col}", fontsize=13)
    ax.set_xlabel(col)
    ax.set_ylabel("Densidade")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def _boxplots(dfs: dict[str, pd.DataFrame], out: Path) -> None:
    fig, axes = plt.subplots(2, 5, figsize=(18, 8))
    axes_flat = axes.flatten()
    for i, col in enumerate(CANON_FEATURES):
        ax = axes_flat[i]
        data_clipped = []
        for df in dfs.values():
            s = df[col].dropna()
            q99 = float(s.quantile(0.99)) if len(s) > 0 else 1.0
            data_clipped.append(s[s <= q99])
        bp = ax.boxplot(data_clipped, tick_labels=list(dfs.keys()),
                        patch_artist=True, notch=False)
        for patch, name in zip(bp["boxes"], dfs.keys()):
            patch.set_facecolor(_PALETTE.get(name, "#888"))
            patch.set_alpha(0.7)
        ax.set_title(col, fontsize=9)
        ax.tick_params(axis="x", labelsize=7, rotation=15)
    fig.suptitle("Boxplots por feature — Real vs Ferramenta", fontsize=13)
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def _scatter(df_real: pd.DataFrame, df_tool: pd.DataFrame, out: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    for ax, (df, title) in zip(axes,
                                [(df_real, "Real (rede-isolada)"), (df_tool, "Ferramenta")]):
        for label, color in _LABEL_COLORS.items():
            sub = df[df["label"] == label]
            ax.scatter(sub["flow_pkts_s"], sub["pkt_len_std"],
                       alpha=0.3, s=8, c=color, label=label)
        ax.set_xlabel("flow_pkts_s")
        ax.set_ylabel("pkt_len_std")
        ax.set_xlim(left=0)
        ax.set_ylim(bottom=0)
        ax.set_title(title)
        ax.legend()
    fig.suptitle("Dispersao: flow_pkts_s x pkt_len_std  (normal=verde, dos=vermelho)",
                 fontsize=12)
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def _heatmap(df: pd.DataFrame, title: str, out: Path) -> None:
    corr = df[CANON_FEATURES].corr()
    fig, ax = plt.subplots(figsize=(10, 8))
    im = ax.imshow(corr.values, aspect="auto", cmap="coolwarm", vmin=-1, vmax=1)
    ax.set_xticks(range(len(CANON_FEATURES)))
    ax.set_yticks(range(len(CANON_FEATURES)))
    ax.set_xticklabels(CANON_FEATURES, rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(CANON_FEATURES, fontsize=8)
    plt.colorbar(im, ax=ax)
    ax.set_title(f"Correlacao de features — {title}", fontsize=12)
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


# ------------------------------------------------------------------ report

def _label_dist(df: pd.DataFrame) -> dict[str, int]:
    return {str(k): int(v) for k, v in df["label"].value_counts().items()}


def _write_report(metrics: dict, out: Path) -> None:
    lines: list[str] = []
    lines += [
        "# Comparacao: VulnForge AI vs Dataset Real SBSeg 2024\n",
        "## Visao Geral dos Datasets\n",
        "| Dataset | Total de Fluxos | Normal | DoS |",
        "|---|---|---|---|",
    ]
    for name, info in metrics["datasets"].items():
        ld = info["label_dist"]
        lines.append(f"| {name} | {info['rows']} | {ld.get('normal', 0)} | {ld.get('dos', 0)} |")

    lines += [
        "\n## Distancias de Distribuicao (Ferramenta vs Rede-Isolada)\n",
        "Referencia: KS < 0.1 excelente, < 0.2 bom, < 0.3 aceitavel, >= 0.3 divergente\n",
        "| Feature | KS | KS p-value | Wasserstein | Jensen-Shannon |",
        "|---|---|---|---|---|",
    ]
    for col in CANON_FEATURES:
        d = metrics["features"][col]["distances"]["tool_vs_isolada"]
        if d["ks"] is None:
            lines.append(f"| {col} | N/A | N/A | N/A | N/A |")
        else:
            lines.append(
                f"| {col} | {d['ks']:.4f} | {d['ks_p']:.2e} "
                f"| {d['wasserstein']:.4f} | {d['js']:.4f} |"
            )

    lines += [
        "\n## Estatisticas por Feature (media +/- desvio padrao)\n",
        "| Feature | Real Aberta | Real Isolada | Ferramenta |",
        "|---|---|---|---|",
    ]
    for col in CANON_FEATURES:
        s = metrics["features"][col]["stats"]

        def fmt(name: str) -> str:
            d = s[name]
            if d["mean"] is None:
                return "N/A"
            return f"{d['mean']:.3g} +/- {d['std']:.3g}"

        lines.append(
            f"| {col} | {fmt('real_aberta')} | {fmt('real_isolada')} | {fmt('tool')} |"
        )

    lines += [
        "\n## Metodologia\n",
        "- **Real**: Dataset SBSeg 2024 com dispositivos IoT reais (NodeMCU V3, ESP32, STM32)",
        "  capturado com Java CICFlowMeter (84 colunas, tempo em microsegundos).",
        "- **Ferramenta**: VulnForge AI gerando trafego XRCE-DDS em loopback (UDP 7400),",
        "  3 sensores virtuais, capturado com Python cicflowmeter (10 colunas, tempo em s).",
        "- **Harmonizacao**: 10 features comuns; `flow_duration`, `fwd_iat_mean`,",
        "  `bwd_iat_mean` convertidos de microsegundos para segundos no dataset real.",
        "- **Distancias**: KS (Kolmogorov-Smirnov), Wasserstein (Earth Mover Distance),",
        "  Jensen-Shannon Divergence (baseada em histograma de 50 bins).\n",
        "## Limitacoes\n",
        "- Escala: ferramenta gera poucos mil fluxos vs 28-31 mil do dataset real.",
        "- A ferramenta equivale a **rede isolada** (sem interferencia residencial).",
        "- Payload da ferramenta e aleatorio; dispositivos reais enviam dados de sensores.",
        "- Trafego backward via `agent_sink.py` (echo simples) e mais simples que o agente real.",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")


# ------------------------------------------------------------------ main

def main() -> None:
    global REPORTS_DIR, FIGS_DIR

    parser = argparse.ArgumentParser(description="Comparacao VulnForge AI vs SBSeg 2024")
    parser.add_argument(
        "--tool-dataset",
        default=str(REPO / "data" / "sbseg2024" / "tool" / "xrce_dds_tool.csv"),
        help="Caminho para o dataset gerado pela ferramenta",
    )
    parser.add_argument(
        "--reports-dir",
        default=str(REPORTS_DIR),
        help="Diretorio de saida para metrics.json, comparacao.md e figs/ "
             "(default: reports/sbseg2024). Use reports/sbseg2024_v2 para a versao ESP8266.",
    )
    args = parser.parse_args()

    # Permite saida lado a lado (v2) sem sobrescrever artefatos anteriores.
    REPORTS_DIR = Path(args.reports_dir)
    FIGS_DIR = REPORTS_DIR / "figs"

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGS_DIR.mkdir(parents=True, exist_ok=True)
    HARMONIZED_DIR.mkdir(parents=True, exist_ok=True)

    tool_path = Path(args.tool_dataset)
    if not tool_path.exists():
        print(
            f"ERRO: dataset da ferramenta nao encontrado: {tool_path}\n"
            "Execute primeiro:\n"
            "  sudo -E env PATH=$PATH python scripts/sbseg2024/run_testbed.py",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Carregando datasets...")
    df_aberta, df_isolada = _load_real(
        REAL_DIR / "monitory_envio-rede-aberta.csv",
        REAL_DIR / "monitory_envio-rede-isolada.csv",
    )
    df_tool = _load_tool(tool_path)

    df_aberta.to_csv(HARMONIZED_DIR / "real_aberta.csv", index=False)
    df_isolada.to_csv(HARMONIZED_DIR / "real_isolada.csv", index=False)
    df_tool.to_csv(HARMONIZED_DIR / "tool.csv", index=False)
    print(f"  Datasets harmonizados: {HARMONIZED_DIR}/")

    dfs = {"real_aberta": df_aberta, "real_isolada": df_isolada, "tool": df_tool}

    # Metricas
    print("Calculando metricas...")
    metrics: dict = {
        "datasets": {
            name: {"rows": len(df), "label_dist": _label_dist(df)}
            for name, df in dfs.items()
        },
        "features": {},
        "by_label": {},
    }

    for col in CANON_FEATURES:
        metrics["features"][col] = {
            "stats": {name: _desc(df[col]) for name, df in dfs.items()},
            "distances": {
                "tool_vs_isolada": _distances(df_tool[col], df_isolada[col]),
                "tool_vs_aberta": _distances(df_tool[col], df_aberta[col]),
                "aberta_vs_isolada": _distances(df_aberta[col], df_isolada[col]),
            },
        }

    for label in ("normal", "dos"):
        subs = {name: df[df["label"] == label] for name, df in dfs.items()}
        metrics["by_label"][label] = {
            col: {
                "stats": {name: _desc(sub[col]) for name, sub in subs.items()},
                "distance_tool_vs_isolada": _distances(
                    subs["tool"][col], subs["real_isolada"][col]
                ),
            }
            for col in CANON_FEATURES
        }

    metrics_path = REPORTS_DIR / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Metricas: {metrics_path}")

    # Figuras
    print("Gerando figuras...")
    for col in CANON_FEATURES:
        _hist(dfs, col, FIGS_DIR / f"hist_{col}.png")
    _boxplots(dfs, FIGS_DIR / "boxplots_all.png")
    _scatter(df_isolada, df_tool, FIGS_DIR / "scatter_pkts_std.png")
    _heatmap(df_isolada, "Real (rede-isolada)", FIGS_DIR / "corr_real.png")
    _heatmap(df_tool, "Ferramenta", FIGS_DIR / "corr_tool.png")
    print(f"  Figuras: {FIGS_DIR}/")

    # Relatorio
    print("Gerando relatorio...")
    _write_report(metrics, REPORTS_DIR / "comparacao.md")
    print(f"  Relatorio: {REPORTS_DIR / 'comparacao.md'}")

    print("\nConcluido! Execute o proximo passo:")
    print("  python scripts/sbseg2024/make_comparison_deck.py")


if __name__ == "__main__":
    main()
