"""Harmoniza schemas CICFlowMeter para conjunto canonico de 10 features.

Suporte a:
  - Python cicflowmeter (10 colunas snake_case, tempo em segundos)
  - Java CICFlowMeter / SBSeg 2024 (84 colunas com espacos, tempo em microsegundos)

Uso como modulo:
    from scripts.sbseg2024.harmonize import harmonize, CANON_FEATURES
    df_canon = harmonize(df, source="sbseg")   # ou source="tool"
"""
from __future__ import annotations

import pandas as pd

# Java CICFlowMeter (SBSeg) → canonico
SBSEG_TO_CANON: dict[str, str] = {
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "tot_fwd_pkts",
    "Tot Bwd Pkts": "tot_bwd_pkts",
    "Fwd Pkt Len Mean": "fwd_pkt_len_mean",
    "Bwd Pkt Len Mean": "bwd_pkt_len_mean",
    "Flow Byts/s": "flow_byts_s",
    "Flow Pkts/s": "flow_pkts_s",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Pkt Len Std": "pkt_len_std",
    "Label": "label",
}

# Python cicflowmeter → canonico (com aliases para variacao de versao)
TOOL_TO_CANON: dict[str, str] = {
    "flow_duration": "flow_duration",
    "total_fwd_packets": "tot_fwd_pkts",
    "tot_fwd_pkts": "tot_fwd_pkts",
    "total_bwd_packets": "tot_bwd_pkts",
    "tot_bwd_pkts": "tot_bwd_pkts",
    "fwd_packet_len_mean": "fwd_pkt_len_mean",
    "fwd_pkt_len_mean": "fwd_pkt_len_mean",
    "bwd_packet_len_mean": "bwd_pkt_len_mean",
    "bwd_pkt_len_mean": "bwd_pkt_len_mean",
    "flow_bytes_s": "flow_byts_s",
    "flow_byts_s": "flow_byts_s",
    "flow_packets_s": "flow_pkts_s",
    "flow_pkts_s": "flow_pkts_s",
    "fwd_iat_mean": "fwd_iat_mean",
    "bwd_iat_mean": "bwd_iat_mean",
    "packet_len_std": "pkt_len_std",
    "pkt_len_std": "pkt_len_std",
    "label": "label",
}

CANON_FEATURES: list[str] = [
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_byts_s",
    "flow_pkts_s",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "pkt_len_std",
]

# Colunas de tempo no dataset SBSeg reportadas em microsegundos pelo Java CICFlowMeter
_SBSEG_MICROS: set[str] = {"flow_duration", "fwd_iat_mean", "bwd_iat_mean"}

_LABEL_MAP: dict[str, str] = {
    "DoS": "dos",
    "dos": "dos",
    "flooding": "dos",
    "Normal": "normal",
    "normal": "normal",
    "baseline": "normal",
    "BENIGN": "normal",
}


def harmonize(df: pd.DataFrame, source: str) -> pd.DataFrame:
    """Retorna DataFrame com colunas canonicas e labels normalizados.

    Args:
        df: DataFrame a harmonizar.
        source: ``"sbseg"`` para Java CICFlowMeter; ``"tool"`` para Python cicflowmeter.

    Returns:
        DataFrame com as 10 colunas canonicas + ``label``, tudo numerico.
    """
    if source not in ("sbseg", "tool"):
        raise ValueError(f"source deve ser 'sbseg' ou 'tool', nao '{source}'")

    mapping = SBSEG_TO_CANON if source == "sbseg" else TOOL_TO_CANON
    rename = {col: mapping[col] for col in df.columns if col in mapping}
    df = df.rename(columns=rename).copy()

    # Converte microsegundos → segundos nas colunas de tempo do dataset SBSeg
    if source == "sbseg":
        for col in _SBSEG_MICROS:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce") / 1_000_000.0

    # Garante todas as colunas canonicas (NaN se ausente)
    for col in CANON_FEATURES:
        if col not in df.columns:
            df[col] = float("nan")

    # Converte features para numerico
    for col in CANON_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Normaliza labels
    if "label" in df.columns:
        df["label"] = df["label"].map(
            lambda v: _LABEL_MAP.get(str(v).strip(), str(v).strip().lower())
        )
    else:
        df["label"] = "unknown"

    return df[CANON_FEATURES + ["label"]].copy()
