"""CLI do VulnForge AI (protoforge)."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .config import get_settings
from .db import get_connection
from .llm import analyzer
from .logging_setup import get_logger, setup_logging
from .protocols import registry
from .scenarios import generator, schema
from .traffic import docker_gen, runner
from .vulnerability import collector, repository


def _apply_model_overrides(provider: str | None, model: str | None) -> None:
    """Sobrescreve provider/model nas settings em runtime (flags --provider/--model)."""
    settings = get_settings()
    if provider:
        settings.llm_provider = provider
    if model:
        settings.llm_model = model

app = typer.Typer(
    help="VulnForge AI - vuln -> analise -> cenario -> dataset -> IDS (DDS/XRCE-DDS/Zenoh).",
    no_args_is_help=True,
    add_completion=False,
)
log = get_logger(__name__)


@app.callback()
def _main() -> None:
    setup_logging(get_settings().log_level)


@app.command("import-vulns")
def import_vulns(file: str = typer.Option(..., "--file", help="JSON/CSV de vulnerabilidades")):
    """Importa vulnerabilidades de um arquivo JSON/CSV para o SQLite."""
    vulns = collector.import_vulns(file)
    typer.echo(f"Importadas {len(vulns)} vulnerabilidades:")
    for v in vulns:
        typer.echo(f"  - {v.id} | {v.severity} | {v.title[:60]}")


@app.command()
def analyze(
    vuln_id: str = typer.Option(None, "--vuln-id", help="ID da vuln ja importada"),
    text: str = typer.Option(None, "--text", help="Descricao textual livre"),
    protocol: str = typer.Option(None, "--protocol", help="Dica de protocolo (XRCE-DDS, Zenoh, DDS...)"),
    provider: str = typer.Option(None, "--provider", help="LLM provider: openrouter|local|offline"),
    model: str = typer.Option(None, "--model", help="Modelo LLM (ex.: qwen2.5-coder:32b)"),
):
    """Analisa uma vuln/descricao e retorna JSON estruturado (LLM ou rule-based)."""
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
        result = analyzer.analyze(text, protocol=protocol)
    else:
        raise typer.BadParameter("Informe --vuln-id ou --text.")

    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False))


@app.command("generate-scenario")
def generate_scenario(
    vuln_id: str = typer.Option(None, "--vuln-id", help="ID da vuln (usa analise salva ou gera)"),
    text: str = typer.Option(None, "--text", help="Descricao textual livre"),
    protocol: str = typer.Option(None, "--protocol"),
    target: str = typer.Option("127.0.0.1", "--target", help="Alvo de laboratorio (IP privado)"),
    interface: str = typer.Option("any", "--interface"),
    duration: int = typer.Option(30, "--duration"),
    native: bool = typer.Option(False, "--native", help="Usar ataque Python nativo em vez de container"),
    out: str = typer.Option(..., "--out", help="Caminho do YAML de saida"),
):
    """Gera um cenario YAML a partir da analise de uma vuln/descricao."""
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
        analysis, vuln=vuln, target=target, interface=interface,
        duration=duration, prefer_container=not native,
    )
    path = schema.dump_scenario(scenario, out)
    typer.echo(f"Cenario gerado: {path}")


@app.command("run-scenario")
def run_scenario(
    file: str = typer.Option(..., "--file", help="YAML do cenario"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Apenas imprime comandos"),
    execute: bool = typer.Option(False, "--execute", help="Executa de verdade (lab only)"),
    yes: bool = typer.Option(False, "--yes", help="Confirma execucao real sem prompt"),
    validate: bool = typer.Option(False, "--validate", help="Roda harness de efeito (sonda+pcap)"),
    vuln_id: str = typer.Option("", "--vuln-id"),
):
    """Executa (ou imprime, em dry-run) o cenario: tcpdump + trafego normal + ataque."""
    scenario = schema.load_scenario(file)
    if execute and not dry_run and not yes:
        yes = typer.confirm(
            f"Executar ataque REAL do cenario '{scenario.scenario_id}' contra alvos de laboratorio?",
            default=False,
        )
    try:
        record = runner.run_scenario(
            scenario, dry_run=dry_run, execute=execute, assume_yes=yes, vuln_id=vuln_id,
            validate=validate,
        )
    except Exception as exc:  # erros de seguranca/permissao com mensagem clara
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(f"run_id={record.run_id} status={record.status}")
    if record.status != "dry-run":
        typer.echo(f"  pcap: {record.pcap_path}")
        typer.echo(f"  log:  {record.log_path}")
        if validate:
            typer.echo(f"  veredito de efeito: {record.effect_verdict} "
                       f"(antes={record.responsive_before} depois={record.responsive_after})")
            if record.anomalies:
                typer.echo(f"  anomalias: {record.anomalies}")


@app.command("build-dataset")
def build_dataset(
    flows: str = typer.Option(..., "--flows", help="CSV de flows ou PCAP"),
    label: str = typer.Option(..., "--label", help="Rotulo a aplicar"),
    out: str = typer.Option(..., "--out", help="CSV de saida"),
    label_column: str = typer.Option("label", "--label-column"),
):
    """Gera um dataset CSV rotulado a partir de flows/PCAP + metadata JSON."""
    from .dataset import builder

    try:
        meta = builder.build_dataset(flows, label, out, label_column=label_column)
    except RuntimeError as exc:  # CICFlowMeter ausente etc.
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Dataset: {out} ({meta.rows} linhas, labels={meta.labels})")


@app.command("train-ids")
def train_ids(
    dataset: str = typer.Option(..., "--dataset", help="CSV rotulado"),
    label_column: str = typer.Option("label", "--label-column"),
    test_size: float = typer.Option(0.3, "--test-size"),
):
    """Treina IDS baseline (RandomForest + LogisticRegression) e gera relatorio."""
    from .ids import trainer

    result = trainer.train(dataset, label_column=label_column, test_size=test_size)
    typer.echo(json.dumps(trainer.result_to_dict(result), indent=2, ensure_ascii=False))


@app.command()
def report(
    run_id: str = typer.Option(..., "--run-id", help="ID do run a relatar"),
    out: str = typer.Option(None, "--out", help="Caminho do .md (default reports/<run_id>.md)"),
):
    """Gera o relatorio Markdown end-to-end de um run."""
    from .reports import generator as report_gen

    path = report_gen.build_report(run_id, out_path=out)
    typer.echo(f"Relatorio: {path}")


@app.command("gen-attack-docker")
def gen_attack_docker(
    type: str = typer.Option("all", "--type", help=f"Tipo: all|{'/'.join(docker_gen.ATTACK_TYPES)}"),
    out: str = typer.Option("docker/attacks", "--out", help="Diretorio de saida"),
):
    """Gera Dockerfile(s) que empacotam os ataques nativos Python."""
    types = docker_gen.ATTACK_TYPES if type == "all" else [type]
    for attack in types:
        path = docker_gen.generate_dockerfile(attack, out)
        typer.echo(f"Dockerfile gerado: {path}")


@app.command("forge-attack")
def forge_attack(
    vuln_id: str = typer.Option(None, "--vuln-id", help="ID da vuln ja importada"),
    text: str = typer.Option(None, "--text", help="Descricao textual livre da ameaca"),
    protocol: str = typer.Option(None, "--protocol", help="Dica de protocolo"),
    target: str = typer.Option("127.0.0.1", "--target", help="Alvo de laboratorio (IP privado)"),
    out_code: str = typer.Option("generated/attacks", "--out-code", help="Dir do .py gerado"),
    out_docker: str = typer.Option("docker/attacks", "--out-docker", help="Dir do bundle Docker"),
    no_docker: bool = typer.Option(False, "--no-docker", help="Nao gerar bundle Docker"),
    scenario_out: str = typer.Option(None, "--scenario-out", help="Tambem gravar cenario YAML"),
    provider: str = typer.Option(None, "--provider", help="LLM provider: openrouter|local|offline"),
    model: str = typer.Option(None, "--model", help="Modelo LLM (ex.: qwen2.5-coder:32b)"),
):
    """Sintetiza um ataque a partir do CVE/descricao (LLM ou fallback) e gera o Docker.

    A mensagem-base vem do plugin REAL do protocolo; o LLM gera so a mutacao maliciosa,
    validada num sandbox (sem imports/IO) e auto-testada. Use so em laboratorio isolado.
    """
    from .llm import exploit_synth
    from .traffic import codegen, docker_gen

    _apply_model_overrides(provider, model)

    # 1. Obter a analise (protocolo + tipo de ataque) a partir do CVE/descricao.
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

    # 2. Sintetizar a MUTACAO sobre o baseline real do protocolo.
    try:
        synth = exploit_synth.synthesize(source_text, analysis)
    except codegen.CodeValidationError as exc:
        raise typer.BadParameter(f"Codigo sintetizado invalido: {exc}") from exc

    base = vuln.id if vuln else (analysis.protocol or "attack")
    scenario_id = generator._slug(f"{base}_{analysis.protocol}_{synth.strategy}")
    label = analysis.dataset_label or scenario_id
    grounded = registry.get(analysis.protocol) is not None

    # 3. Renderizar + validar + escrever o modulo Python (mutator sobre baseline real).
    module = codegen.render_mutator_module(
        scenario_id=scenario_id, protocol=analysis.protocol, strategy=synth.strategy,
        source=synth.source, rationale=synth.rationale, mutator_code=synth.mutator_code,
        port=synth.port, transport=synth.transport, duration=synth.duration, rate=synth.rate,
        label=label,
    )
    code_path = codegen.write_attack_module(module, scenario_id, out_code)

    grounding = "ancorado em plugin real" if grounded else "SEM plugin (unvalidated/wire-level)"
    typer.echo(f"Ataque sintetizado ({synth.source}, {grounding}) -> {code_path}")
    typer.echo(f"  protocolo={analysis.protocol} estrategia={synth.strategy} "
               f"porta={synth.port}/{synth.transport}")
    typer.echo(f"  racional: {synth.rationale[:120]}")

    # 4. Bundle Docker parametrizado (Dockerfile + entrypoint + compose com alvo).
    if not no_docker:
        bundle = docker_gen.generate_synth_bundle(
            scenario_id=scenario_id, protocol=analysis.protocol, strategy=synth.strategy,
            source=synth.source, module_code=module, port=synth.port,
            transport=synth.transport, duration=synth.duration, out_dir=out_docker,
        )
        typer.echo(f"Bundle Docker -> {bundle} (Dockerfile, entrypoint.sh, docker-compose.yml)")

    # 5. (Opcional) gravar cenario YAML apontando para o ataque sintetizado.
    if scenario_out:
        from .models import AttackType, Scenario

        attack_cmd = (
            f"python {code_path} --target {target} --port {synth.port} "
            f"--transport {synth.transport} --duration {int(synth.duration)}"
        )
        try:
            atype = AttackType(synth.strategy)
        except ValueError:
            atype = analysis.likely_attack_type
        scenario = Scenario(
            scenario_id=scenario_id, protocol=analysis.protocol, attack_type=atype,
            duration_seconds=int(synth.duration) + 10,
            normal_traffic_command=(
                f"python -m vulnforge.traffic.attacks.flooding --target {target} "
                f"--port {synth.port} --transport {synth.transport} --rate 5 --duration 20 --benign"
            ),
            attack_command=attack_cmd, capture_interface="any",
            output_pcap=f"data/runs/{scenario_id}.pcap", label=label,
            notes=f"Ataque sintetizado ({synth.source}). {analysis.safety_notes}",
        )
        path = schema.dump_scenario(scenario, scenario_out)
        typer.echo(f"Cenario -> {path}")


@app.command("protocols")
def protocols():
    """Lista os protocolos plugaveis e se a lib real (sessao valida) esta instalada."""
    plugins = registry.available()
    if not plugins:
        typer.echo("Nenhum protocolo registrado.")
        return
    typer.echo("Protocolos registrados:")
    for name, plugin in sorted(plugins.items()):
        dep = "lib real OK" if plugin.is_available() else "fallback (sem lib real)"
        img = plugin.target_image or "-"
        typer.echo(f"  - {plugin.name:10} {plugin.default_port}/{plugin.transport:3} "
                   f"| {dep:24} | alvo: {img}")
        if not plugin.is_available() and plugin.install_hint:
            typer.echo(f"      {plugin.install_hint}")


@app.command("list-vulns")
def list_vulns():
    """Lista as vulnerabilidades importadas."""
    conn = get_connection()
    try:
        for v in repository.list_vulns(conn):
            typer.echo(f"{v.id} | {v.severity} | cvss={v.cvss} | {v.title[:50]}")
    finally:
        conn.close()


if __name__ == "__main__":
    app()
