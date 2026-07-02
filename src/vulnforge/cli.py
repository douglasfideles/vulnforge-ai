"""Command-line interface entry point for protoforge.

This module exposes the ``protoforge`` console script built with Typer.
Each command maps to one stage of the VulnForge pipeline:
vulnerability ingestion, threat analysis, scenario generation, execution,
dataset building, IDS training, reporting and attack synthesis.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .config import get_settings
from .db import get_connection
from .llm import analyzer, exploit_synth
from .logging_setup import get_logger, setup_logging
from .protocols import registry
from .scenarios import generator, schema
from .traffic import docker_gen, runner
from .traffic.codegen import CodeValidationError
from .vulnerability import collector, repository

app = typer.Typer(
    help="VulnForge AI - vuln -> analise -> cenario -> dataset -> IDS (DDS/XRCE-DDS/Zenoh).",
    no_args_is_help=True,
    add_completion=False,
)
log = get_logger(__name__)


def _apply_model_overrides(provider: str | None, model: str | None) -> None:
    """Override LLM provider/model in the process-singleton settings."""
    settings = get_settings()
    if provider:
        settings.llm_provider = provider
    if model:
        settings.llm_model = model


@app.callback()
def _main() -> None:
    """Initialize logging before every command."""
    setup_logging(get_settings().log_level)


@app.command("import-vulns")
def import_vulns(file: str = typer.Option(..., "--file", help="JSON/CSV de vulnerabilidades")):
    """Import vulnerabilities into SQLite."""
    vulns = collector.import_vulns(file)
    conn = get_connection()
    try:
        for vuln in vulns:
            repository.upsert_vuln(conn, vuln)
    finally:
        conn.close()
    typer.echo(f"Importadas {len(vulns)} vulnerabilidades:")
    for v in vulns:
        typer.echo(f"  - {v.id} | {v.severity} | {v.cvss} | {v.title[:60]}")


@app.command("list-vulns")
def list_vulns() -> None:
    """List imported vulnerabilities."""
    conn = get_connection()
    try:
        vulns = repository.list_vulns(conn)
    finally:
        conn.close()
    typer.echo(f"{'id':<30} | {'severity':<10} | {'cvss':<5} | title")
    for v in vulns:
        typer.echo(f"{v.id:<30} | {v.severity:<10} | {str(v.cvss):<5} | {v.title[:60]}")


@app.command()
def analyze(
    vuln_id: str = typer.Option(None, "--vuln-id"),
    text: str = typer.Option(None, "--text"),
    protocol: str = typer.Option(None, "--protocol"),
    provider: str = typer.Option(None, "--provider"),
    model: str = typer.Option(None, "--model"),
):
    """Analyze a vulnerability or free text."""
    _apply_model_overrides(provider, model)
    if vuln_id:
        conn = get_connection()
        try:
            vuln = repository.get_vuln(conn, vuln_id)
            if vuln is None:
                raise typer.BadParameter(f"vuln-id nao encontrado: {vuln_id}")
            result = analyzer.analyze_vuln(vuln, protocol=protocol)
            repository.save_analysis(conn, vuln_id, result)
        finally:
            conn.close()
    elif text:
        result = analyzer.analyze(text, protocol_hint=protocol)
    else:
        raise typer.BadParameter("Informe --vuln-id ou --text.")
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False))


@app.command("generate-scenario")
def generate_scenario(
    vuln_id: str = typer.Option(None, "--vuln-id"),
    text: str = typer.Option(None, "--text"),
    protocol: str = typer.Option(None, "--protocol"),
    target: str = typer.Option("127.0.0.1", "--target"),
    interface: str = typer.Option("any", "--interface"),
    duration: int = typer.Option(30, "--duration"),
    native: bool = typer.Option(False, "--native"),
    out: str = typer.Option(..., "--out"),
):
    """Generate a scenario YAML from a vulnerability/text analysis."""
    vuln = None
    if vuln_id:
        conn = get_connection()
        try:
            vuln = repository.get_vuln(conn, vuln_id)
            if vuln is None:
                raise typer.BadParameter(f"vuln-id nao encontrado: {vuln_id}")
            analysis = repository.get_analysis(conn, vuln_id) or analyzer.analyze_vuln(vuln, protocol=protocol)
            repository.save_analysis(conn, vuln_id, analysis)
        finally:
            conn.close()
    elif text:
        analysis = analyzer.analyze(text, protocol=protocol)
    else:
        raise typer.BadParameter("Informe --vuln-id ou --text.")

    scenario = generator.generate(
        analysis,
        vuln=vuln,
        target=target,
        interface=interface,
        duration=duration,
        prefer_container=not native,
    )
    path = schema.dump_scenario(scenario, out)
    typer.echo(f"Cenario gerado: {path}")


@app.command("run-scenario")
def run_scenario(
    file: str = typer.Option(..., "--file"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run"),
    execute: bool = typer.Option(False, "--execute"),
    yes: bool = typer.Option(False, "--yes"),
    validate: bool = typer.Option(False, "--validate"),
    vuln_id: str = typer.Option("", "--vuln-id"),
):
    """Run a scenario in dry-run or real mode."""
    scenario = schema.load_scenario(file)
    if execute and not dry_run and not yes:
        yes = typer.confirm(
            f"Executar ataque REAL do cenario '{scenario.scenario_id}' contra alvos de laboratorio?",
            default=False,
        )
    try:
        record = runner.run_scenario(
            scenario,
            dry_run=dry_run,
            execute=execute,
            assume_yes=yes,
            vuln_id=vuln_id,
            validate=validate,
        )
    except Exception as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(f"run_id={record.run_id} status={record.status}")
    if record.status != "dry-run":
        typer.echo(f"  pcap: {record.pcap_path}")
        typer.echo(f"  log: {record.log_path}")
        if validate:
            typer.echo(
                f"  veredito: {record.effect_verdict} "
                f"(antes={record.responsive_before} depois={record.responsive_after})"
            )
            if record.anomalies:
                typer.echo(f"  anomalias: {record.anomalies}")


@app.command("build-dataset")
def build_dataset(
    flows: str = typer.Option(..., "--flows"),
    label: str = typer.Option(..., "--label"),
    out: str = typer.Option(..., "--out"),
    label_column: str = typer.Option("label", "--label-column"),
):
    """Build a labeled dataset from CSV flows or PCAP."""
    from .dataset import builder
    try:
        meta = builder.build_dataset(flows, label, out, label_column=label_column)
    except RuntimeError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Dataset: {out} ({meta.rows} linhas, labels={meta.labels})")


@app.command("train-ids")
def train_ids(
    dataset: str = typer.Option(..., "--dataset"),
    label_column: str = typer.Option("label", "--label-column"),
    test_size: float = typer.Option(0.3, "--test-size"),
):
    """Train baseline IDS models."""
    from .ids import trainer
    result = trainer.train(dataset, label_column=label_column, test_size=test_size)
    typer.echo(json.dumps(trainer.result_to_dict(result), indent=2, ensure_ascii=False))


@app.command()
def report(
    run_id: str = typer.Option(..., "--run-id"),
    out: str = typer.Option(None, "--out"),
):
    """Generate end-to-end Markdown report for a run."""
    from .reports import generator as report_gen
    path = report_gen.build_report(run_id, out_path=out)
    typer.echo(f"Relatorio: {path}")


@app.command("gen-attack-docker")
def gen_attack_docker(
    type: str = typer.Option("all", "--type"),
    out: str = typer.Option("docker/attacks", "--out"),
):
    """Generate Dockerfiles for native attacks."""
    types = docker_gen.ATTACK_TYPES if type == "all" else [type]
    for attack in types:
        path = docker_gen.generate_dockerfile(attack, out)
        typer.echo(f"Dockerfile gerado: {path}")


@app.command("forge-attack")
def forge_attack(
    vuln_id: str = typer.Option(None, "--vuln-id"),
    text: str = typer.Option(None, "--text"),
    protocol: str = typer.Option(None, "--protocol"),
    target: str = typer.Option("127.0.0.1", "--target"),
    out_code: str = typer.Option("generated/attacks", "--out-code"),
    out_docker: str = typer.Option("docker/attacks", "--out-docker"),
    no_docker: bool = typer.Option(False, "--no-docker"),
    scenario_out: str = typer.Option(None, "--scenario-out"),
    provider: str = typer.Option(None, "--provider"),
    model: str = typer.Option(None, "--model"),
):
    """Synthesize an attack module from a CVE/text."""
    from .traffic import codegen, docker_gen
    _apply_model_overrides(provider, model)

    vuln = None
    if vuln_id:
        conn = get_connection()
        try:
            vuln = repository.get_vuln(conn, vuln_id)
            if vuln is None:
                raise typer.BadParameter(f"vuln-id nao encontrado: {vuln_id}")
            source_text = analyzer.vuln_to_text(vuln)
            analysis = repository.get_analysis(conn, vuln_id) or analyzer.analyze_vuln(vuln, protocol=protocol)
            repository.save_analysis(conn, vuln_id, analysis)
        finally:
            conn.close()
    elif text:
        source_text = text
        analysis = analyzer.analyze(text, protocol=protocol)
    else:
        raise typer.BadParameter("Informe --vuln-id ou --text.")

    try:
        synth = exploit_synth.synthesize(source_text, analysis)
    except CodeValidationError as exc:
        raise typer.BadParameter(f"Codigo sintetizado invalido: {exc}") from exc

    scenario_id = f"{_slug(analysis.protocol)}_{_slug(analysis.likely_attack_type.value)}"
    code_path = Path(out_code) / f"{scenario_id}.py"
    code_path.parent.mkdir(parents=True, exist_ok=True)
    code_path.write_text(
        _render_attack_module(scenario_id, analysis, synth, target),
        encoding="utf-8",
    )
    typer.echo(f"Modulo gerado: {code_path}")

    if not no_docker:
        module = {
            "flooding": "flooding",
            "replay": "replay",
            "malformed_message": "malformed",
            "oversized_payload": "oversized",
            "injection_simulated": "malformed",
        }.get(analysis.likely_attack_type.value, "fuzz")
        bundle = docker_gen.generate_bundle(scenario_id, module, out_docker)
        typer.echo(f"Bundle Docker: {bundle}")

    if scenario_out:
        from .scenarios.generator import generate as gen_scenario
        scenario = gen_scenario(analysis, vuln=vuln, target=target)
        schema.dump_scenario(scenario, scenario_out)
        typer.echo(f"Cenario: {scenario_out}")


@app.command("protocols")
def list_protocols() -> None:
    """List registered protocol plugins."""
    plugins = registry.available()
    typer.echo(f"{'nome':<15} | {'port':<6} | {'transport':<6} | {'disponivel':<10} | imagem/hint")
    for name, cls in plugins.items():
        available = "sim" if cls.is_available() else "nao"
        image = cls.target_image or "-"
        hint = cls.install_hint or ""
        typer.echo(
            f"{name:<15} | {cls.default_port:<6} | {cls.transport:<6} | {available:<10} | {image} {hint}"
        )


def _slug(value: str) -> str:
    return value.lower().replace("-", "_").replace(" ", "_")


def _render_attack_module(
    scenario_id: str,
    analysis: analyzer.ThreatAnalysis,
    synth: exploit_synth.SynthesisResult,
    target: str,
) -> str:
    return f'''"""Generated attack module for {scenario_id}."""

from __future__ import annotations

import random

from vulnforge.protocols.registry import get
from vulnforge.traffic.attacks.common import run_and_report, synth_parser


def _baseline() -> bytes:
    try:
        plugin = get("{analysis.protocol}")()
        return plugin.baseline_message(0)
    except Exception:
        return b""


def mutate(baseline, seq, rng, urandom):
{synth.mutator_code}


def main() -> None:
    baseline = _baseline()
    run_and_report(synth_parser, mutate, baseline=baseline)


if __name__ == "__main__":
    main()
'''


if __name__ == "__main__":
    app()
