"""End-to-end Markdown report generator from a run_id."""

from __future__ import annotations

import json
from pathlib import Path

from ..db import get_connection
from ..logging_setup import get_logger
from ..scenarios.schema import ScenarioValidationError, load_scenario
from ..vulnerability.repository import get_analysis, get_run, get_vuln

logger = get_logger(__name__)


def _find_dataset_meta(pcap_path: str) -> dict | None:
    if not pcap_path:
        return None
    pcap = Path(pcap_path)
    candidates = [
        pcap.with_suffix("").with_suffix(".csv.meta.json"),
        pcap.with_suffix(".csv.meta.json"),
        Path("data/datasets") / f"{pcap.stem}.csv.meta.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
    return None


def build_report(run_id: str, out_path: str | None = None) -> Path:
    """Build a Markdown report from a persisted run_id."""
    conn = get_connection()
    try:
        record = get_run(conn, run_id)
    finally:
        conn.close()

    if record is None:
        raise ValueError(f"Run nao encontrado: {run_id}")

    scenario: object | None = None
    if record.pcap_path:
        yaml_path = Path(record.pcap_path).parent / f"{run_id}.yaml"
        if yaml_path.exists():
            try:
                scenario = load_scenario(yaml_path)
            except ScenarioValidationError:
                scenario = None

    vuln = None
    analysis = None
    if record.vuln_id:
        conn = get_connection()
        try:
            vuln = get_vuln(conn, record.vuln_id)
            analysis = get_analysis(conn, record.vuln_id)
        finally:
            conn.close()

    dataset_meta = _find_dataset_meta(record.pcap_path)

    out = Path(out_path) if out_path else Path("reports") / f"{run_id}.md"
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# Relatorio VulnForge AI - {run_id}",
        "",
        f"- **run_id:** `{record.run_id}`",
        f"- **scenario_id:** `{record.scenario_id}`",
        f"- **status:** {record.status}",
        f"- **inicio:** {record.started_at}",
        "",
        "## Cenario",
        "",
    ]
    if scenario:
        lines.extend([
            f"- **protocolo:** {scenario.protocol}",
            f"- **attack_type:** {scenario.attack_type.value}",
            f"- **duracao:** {scenario.duration_seconds}s",
            f"- **interface:** {scenario.capture_interface}",
            f"- **pcap:** `{scenario.output_pcap}`",
            f"- **label:** `{scenario.label}`",
            "",
            "### Comandos",
            "",
            f"**Normal:** `{scenario.normal_traffic_command}`",
            "",
            f"**Ataque:** `{scenario.attack_command}`",
            "",
        ])
    else:
        lines.append("Cenario YAML nao disponivel.\n")

    lines.extend(["## Vulnerabilidade", ""])
    if vuln:
        lines.extend([
            f"- **id:** {vuln.id}",
            f"- **titulo:** {vuln.title}",
            f"- **cvss:** {vuln.cvss}",
            f"- **severidade:** {vuln.severity}",
            "",
        ])
    else:
        lines.append("Vulnerabilidade nao vinculada.\n")

    lines.extend(["## Analise de Ameaca", ""])
    if analysis:
        lines.extend([
            f"- **protocolo:** {analysis.protocol}",
            f"- **tipo provavel:** {analysis.likely_attack_type.value}",
            f"- **label dataset:** `{analysis.dataset_label}`",
            f"- **confianca:** {analysis.confidence}",
            f"- **fonte:** {analysis.source}",
            f"- **notas de seguranca:** {analysis.safety_notes}",
            "",
        ])
    else:
        lines.append("Analise nao disponivel.\n")

    lines.extend(["## Validacao de Efeito", ""])
    if record.effect_verdict != "not_validated":
        lines.extend([
            f"- **veredito:** {record.effect_verdict}",
            f"- **responsivo antes:** {record.responsive_before}",
            f"- **responsivo depois:** {record.responsive_after}",
            f"- **anomalias:** {record.anomalies}",
            "",
        ])
    else:
        lines.append("Efeito nao validado nesta execucao.\n")

    lines.extend(["## Dataset", ""])
    if dataset_meta:
        lines.extend([
            f"- **fonte:** {dataset_meta.get('source_file', '')}",
            f"- **linhas:** {dataset_meta.get('rows', 0)}",
            f"- **labels:** {dataset_meta.get('labels', [])}",
            "",
        ])
    else:
        lines.append("Dataset nao encontrado para este run.\n")

    if record.llm_model:
        lines.extend([
            "## Reprodutibilidade",
            "",
            f"- **modelo LLM:** {record.llm_model}",
            f"- **seed LLM:** {record.llm_seed}",
            "",
        ])

    out.write_text("\n".join(lines), encoding="utf-8")
    return out
