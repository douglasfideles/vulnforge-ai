"""Geracao do relatorio Markdown end-to-end a partir de um run_id."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..db import get_connection
from ..logging_setup import get_logger
from ..models import Scenario
from ..vulnerability import repository

log = get_logger(__name__)

LIMITATIONS = (
    "- Cenarios sao sinteticos e executados em laboratorio isolado; nao refletem todas as "
    "condicoes de redes reais.\n"
    "- Datasets podem ser pequenos/desbalanceados; metricas do IDS sao baseline, nao producao.\n"
    "- Ataques sao controlados e restritos a alvos privados; cobertura de variantes e parcial.\n"
    "- A analise via LLM/regras e um apoio heuristico e pode conter imprecisoes.\n"
)


def _load_dataset_meta(pcap_path: str) -> dict | None:
    """Tenta localizar um meta.json de dataset derivado do mesmo run (best-effort)."""
    if not pcap_path:
        return None
    candidate = Path(pcap_path).with_suffix(".csv.meta.json")
    if candidate.exists():
        return json.loads(candidate.read_text(encoding="utf-8"))
    return None


def build_report(run_id: str, out_path: str | Path | None = None) -> Path:
    """Monta o relatorio Markdown de um run e o salva. Retorna o caminho."""
    conn = get_connection()
    try:
        run = repository.get_run(conn, run_id)
        if run is None:
            raise ValueError(f"run_id nao encontrado: {run_id}")

        vuln = repository.get_vuln(conn, run["vuln_id"]) if run.get("vuln_id") else None
        analysis = repository.get_analysis(conn, run["vuln_id"]) if run.get("vuln_id") else None
    finally:
        conn.close()

    scenario = None
    if run.get("scenario_yaml"):
        try:
            scenario = Scenario.model_validate_json(run["scenario_yaml"])
        except Exception:  # noqa: BLE001
            scenario = None

    md = _render(run, vuln, analysis, scenario)

    out_path = Path(out_path) if out_path else Path("reports") / f"{run_id}.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    log.info("Relatorio gerado: %s", out_path)
    return out_path


def _render(run, vuln, analysis, scenario) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Relatorio VulnForge AI - {run['run_id']}",
        "",
        f"_Gerado em {now}_",
        "",
        "## 1. Vulnerabilidade",
        "",
    ]
    if vuln:
        lines += [
            f"- **ID:** {vuln.id}",
            f"- **Titulo:** {vuln.title}",
            f"- **CVSS:** {vuln.cvss}  | **Severidade:** {vuln.severity}",
            f"- **CWE:** {vuln.cwe}  | **Produto:** {vuln.affected_product}",
            f"- **Fonte:** {vuln.source}  | **Publicado:** {vuln.published_at}",
            "",
            f"> {vuln.description}",
            "",
        ]
    else:
        lines += ["_Sem vulnerabilidade associada a este run._", ""]

    lines += ["## 2. Analise (LLM / regras)", ""]
    if analysis:
        lines += [
            f"- **Fonte da analise:** {analysis.source}",
            f"- **Protocolo:** {analysis.protocol}",
            f"- **Tipo de ataque:** {analysis.likely_attack_type.value}",
            f"- **Confianca:** {analysis.confidence:.2f}",
            f"- **Pre-condicoes:** {analysis.preconditions}",
            f"- **Comportamento esperado:** {analysis.expected_network_behavior}",
            f"- **Label do dataset:** {analysis.dataset_label}",
            f"- **Notas de seguranca:** {analysis.safety_notes}",
            "",
        ]
    else:
        lines += ["_Sem analise registrada._", ""]

    lines += ["## 3. Cenario gerado", ""]
    if scenario:
        lines += [
            f"- **scenario_id:** {scenario.scenario_id}",
            f"- **attack_type:** {scenario.attack_type.value}",
            f"- **duracao:** {scenario.duration_seconds}s",
            f"- **comando normal:** `{scenario.normal_traffic_command or '-'}`",
            f"- **comando ataque:** `{scenario.attack_command or '-'}`",
            f"- **interface:** {scenario.capture_interface}",
            "",
        ]
    else:
        lines += ["_Sem cenario serializado._", ""]

    lines += [
        "## 4. Execucao e artefatos",
        "",
        f"- **Status:** {run['status']}",
        f"- **Iniciado em:** {run['started_at']}",
        f"- **PCAP:** `{run.get('pcap_path') or '-'}`",
        f"- **Log:** `{run.get('log_path') or '-'}`",
        "",
        "### Validacao de efeito (harness)",
        "",
        f"- **Veredito:** {run.get('effect_verdict') or 'not_validated'}",
        f"- **Responsivo antes/depois:** {run.get('responsive_before') or '-'} / "
        f"{run.get('responsive_after') or '-'}",
        f"- **Anomalias:** {run.get('anomalies') or '-'}",
        "",
        "### Reprodutibilidade (LLM)",
        "",
        f"- **Modelo:** {run.get('llm_model') or '-'}  | **Seed:** {run.get('llm_seed') or '-'}",
        "",
    ]

    meta = _load_dataset_meta(run.get("pcap_path", ""))
    lines += ["## 5. Dataset", ""]
    if meta:
        lines += [
            f"- **Nome:** {meta['name']}",
            f"- **Registros:** {meta['rows']}",
            f"- **Labels:** {', '.join(meta['labels'])}",
            "",
        ]
    else:
        lines += ["_Nenhum dataset localizado para este run._", ""]

    lines += [
        "## 6. IDS Baseline",
        "",
        "_Treine com `protoforge train-ids` e referencie o relatorio gerado "
        "(`*_ids_report.md`) ao lado do modelo `.joblib`._",
        "",
        "## 7. Limitacoes",
        "",
        LIMITATIONS,
    ]
    return "\n".join(lines)
