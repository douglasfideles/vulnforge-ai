from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from vulnforge.config import get_settings
from vulnforge.dataset.builder import build_dataset
from vulnforge.db import get_analysis, get_vuln, list_vulns, save_analysis, upsert_vuln
from vulnforge.ids.trainer import train
from vulnforge.llm.analyzer import analyze as analyze_text
from vulnforge.logging_setup import setup_logging
from vulnforge.protocols.registry import available
from vulnforge.protocols.registry import get as get_plugin
from vulnforge.reports.generator import build_report
from vulnforge.scenarios.generator import generate_scenario, load_scenario, save_scenario
from vulnforge.traffic.docker_gen import generate_bundle
from vulnforge.traffic.exploit_synth import forge
from vulnforge.traffic.runner import run_scenario
from vulnforge.vulnerability.normalizer import import_file

app = typer.Typer(no_args_is_help=True, help="Controlled IoT protocol-security research pipeline")


@app.callback()
def main() -> None:
    setup_logging(get_settings().log_level)


def _analysis(vuln_id: str | None, text: str | None, protocol: str, provider: str | None, model: str | None):
    cfg = get_settings()
    if not vuln_id and not text:
        raise typer.BadParameter("Provide either --vuln-id or --text")
    vuln = get_vuln(vuln_id) if vuln_id else None
    if vuln_id and not vuln:
        raise typer.BadParameter(f"Vulnerability {vuln_id!r} was not found")
    overrides = {}
    if provider:
        overrides["llm_provider"] = provider
    if model:
        overrides["llm_model"] = model
    selected = cfg.model_copy(update=overrides)
    result = analyze_text(text or f"{vuln.title}\n{vuln.description}", protocol, selected)
    if vuln_id:
        save_analysis(vuln_id, result)
    return result


@app.command("import-vulns")
def import_vulns(file: Path = typer.Option(..., exists=True, dir_okay=False)) -> None:
    try:
        vulns = import_file(file)
        for vuln in vulns:
            upsert_vuln(vuln)
        typer.echo(f"Imported {len(vulns)} vulnerabilities")
        for vuln in vulns:
            typer.echo(f"{vuln.id} | {vuln.severity} | {vuln.cvss} | {vuln.title}")
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise typer.BadParameter(str(exc)) from None


@app.command("list-vulns")
def list_vulnerabilities() -> None:
    for vuln in list_vulns():
        typer.echo(f"{vuln.id} | {vuln.severity} | {vuln.cvss} | {vuln.title}")


@app.command()
def analyze(
    vuln_id: Optional[str] = typer.Option(None),
    text: Optional[str] = typer.Option(None),
    protocol: str = typer.Option(""),
    provider: Optional[str] = typer.Option(None),
    model: Optional[str] = typer.Option(None),
) -> None:
    typer.echo(_analysis(vuln_id, text, protocol, provider, model).model_dump_json(indent=2))


@app.command("generate-scenario")
def scenario_command(
    out: Path = typer.Option(...),
    vuln_id: Optional[str] = typer.Option(None),
    text: Optional[str] = typer.Option(None),
    protocol: str = typer.Option(""),
    target: str = typer.Option("127.0.0.1"),
    interface: str = typer.Option("any"),
    duration: int = typer.Option(30, min=1, max=3600),
    native: bool = typer.Option(False),
    provider: Optional[str] = typer.Option(None),
    model: Optional[str] = typer.Option(None),
) -> None:
    result = get_analysis(vuln_id) if vuln_id else None
    result = result or _analysis(vuln_id, text, protocol, provider, model)
    path = save_scenario(generate_scenario(result, target, interface, duration, native), out)
    typer.echo(str(path))


@app.command("run-scenario")
def run_command(
    file: Path = typer.Option(..., exists=True, dir_okay=False),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run"),
    execute: bool = typer.Option(False),
    yes: bool = typer.Option(False),
    validate: bool = typer.Option(False),
    vuln_id: str = typer.Option(""),
) -> None:
    try:
        if not dry_run and execute and not yes:
            yes = typer.confirm("Execute this scenario against the restricted lab target?")
        record = run_scenario(load_scenario(file), dry_run=dry_run, execute=execute, confirmed=yes, validate=validate, vuln_id=vuln_id)
        typer.echo(record.model_dump_json(indent=2))
    except (ValueError, RuntimeError) as exc:
        raise typer.BadParameter(str(exc)) from None


@app.command("build-dataset")
def dataset_command(
    flows: Path = typer.Option(..., exists=True, dir_okay=False),
    label: str = typer.Option(...),
    out: Path = typer.Option(...),
    label_column: str = typer.Option("label"),
) -> None:
    try:
        meta = build_dataset(flows, label, out, label_column)
        typer.echo(meta.model_dump_json(indent=2))
    except (ValueError, RuntimeError) as exc:
        raise typer.BadParameter(str(exc)) from None


@app.command("train-ids")
def train_command(
    dataset: Path = typer.Option(..., exists=True, dir_okay=False),
    label_column: str = typer.Option("label"),
    test_size: float = typer.Option(0.3, min=0.05, max=0.95),
) -> None:
    try:
        typer.echo(json.dumps(train(dataset, label_column, test_size), indent=2))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None


@app.command()
def report(run_id: str = typer.Option(...), out: Optional[Path] = typer.Option(None)) -> None:
    try:
        typer.echo(str(build_report(run_id, out)))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None


@app.command("protocols")
def list_protocols() -> None:
    typer.echo("protocol | port/transport | official-lib | target image | install hint")
    for plugin in available():
        typer.echo(f"{plugin.name} | {plugin.default_port}/{plugin.transport} | {plugin.is_available()} | {plugin.target_image or '-'} | {plugin.install_hint or '-'}")


@app.command("forge-attack")
def forge_attack(
    vuln_id: Optional[str] = typer.Option(None),
    text: Optional[str] = typer.Option(None),
    protocol: str = typer.Option(""),
    target: str = typer.Option("127.0.0.1"),
    out_code: Path = typer.Option(Path("generated/attacks")),
    out_docker: Path = typer.Option(Path("docker/attacks")),
    no_docker: bool = typer.Option(False),
    scenario_out: Optional[Path] = typer.Option(None),
    provider: Optional[str] = typer.Option(None),
    model: Optional[str] = typer.Option(None),
) -> None:
    result = _analysis(vuln_id, text, protocol, provider, model)
    code = forge(result, out_code)
    typer.echo(f"code: {code}")
    if not no_docker:
        bundle = generate_bundle(code.stem, code, out_docker)
        typer.echo(f"docker: {bundle}")
    if scenario_out:
        scenario = generate_scenario(result, target=target, native=True)
        plugin = get_plugin(result.protocol)
        port = plugin.default_port if plugin else 9999
        transport = plugin.transport if plugin else "udp"
        scenario.attack_command = f"{__import__('sys').executable} {code} --target {target} --port {port} --transport {transport}"
        save_scenario(scenario, scenario_out)
        typer.echo(f"scenario: {scenario_out}")


@app.command("gen-attack-docker")
def native_docker(
    type: str = typer.Option("all"),
    out: Path = typer.Option(Path("docker/attacks")),
) -> None:
    names = ["flooding", "replay", "fuzz", "oversized", "malformed"] if type == "all" else [type]
    valid = {"flooding", "replay", "fuzz", "oversized", "malformed"}
    for name in names:
        if name not in valid:
            raise typer.BadParameter(f"Unknown attack type {name!r}")
        path = generate_bundle(name, Path(f"-m vulnforge.traffic.attacks.{name}"), out)
        typer.echo(str(path))


if __name__ == "__main__":
    app()
