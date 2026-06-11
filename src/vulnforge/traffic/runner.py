"""Scenario Runner: le YAML, inicia captura tcpdump, roda trafego normal + ataque.

Por padrao opera em dry-run (apenas imprime comandos). Execucao real exige
execute=True e assume_yes=True, alem da guarda de seguranca sobre o alvo.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..config import get_settings
from ..db import get_connection
from ..logging_setup import get_logger
from ..models import RunRecord, Scenario
from ..protocols import registry
from ..validation import harness
from ..vulnerability import repository
from .safety import assert_safe, extract_target

log = get_logger(__name__)


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"run-{stamp}-{uuid.uuid4().hex[:6]}"


def _tcpdump_command(scenario: Scenario) -> str:
    return f"tcpdump -i {scenario.capture_interface} -w {scenario.output_pcap}"


def _targets_from_scenario(scenario: Scenario) -> list[str]:
    """Coleta alvos --target dos comandos para validar seguranca."""
    targets = []
    for cmd in (scenario.normal_traffic_command, scenario.attack_command):
        if not cmd:
            continue
        t = extract_target(cmd)
        if t:
            targets.append(t)
    return targets


def plan_commands(scenario: Scenario) -> list[str]:
    """Lista, em ordem, os comandos que seriam executados."""
    cmds = [_tcpdump_command(scenario)]
    if scenario.normal_traffic_command:
        cmds.append(scenario.normal_traffic_command)
    if scenario.attack_command:
        cmds.append(scenario.attack_command)
    return cmds


def _dry_run(scenario: Scenario, run_id: str) -> RunRecord:
    print(f"# DRY-RUN cenario={scenario.scenario_id} run_id={run_id}")
    print(f"# captura: {scenario.output_pcap} | interface: {scenario.capture_interface}")
    print(f"# duracao: {scenario.duration_seconds}s | alvo: {scenario.label}")
    print("# comandos (NAO executados):")
    for cmd in plan_commands(scenario):
        print(f"  $ {cmd}")
    return RunRecord(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        started_at=datetime.now(timezone.utc).isoformat(),
        status="dry-run",
        pcap_path=scenario.output_pcap,
    )


def _execute(scenario: Scenario, run_id: str, vuln_id: str = "", validate: bool = False) -> RunRecord:
    settings = get_settings()
    runs_dir = settings.runs_dir
    runs_dir.mkdir(parents=True, exist_ok=True)
    Path(scenario.output_pcap).parent.mkdir(parents=True, exist_ok=True)
    log_path = runs_dir / f"{run_id}.log"

    # Seguranca: todo alvo deve ser de laboratorio.
    for target in _targets_from_scenario(scenario):
        assert_safe(target)

    if shutil.which("tcpdump") is None:
        raise RuntimeError("tcpdump nao encontrado no PATH; necessario para captura.")

    started = datetime.now(timezone.utc).isoformat()
    log_lines: list[str] = [f"run_id={run_id} scenario={scenario.scenario_id} started={started}"]

    # Sonda de saude ANTES do ataque (se validate e o protocolo tem plugin).
    plugin = registry.get(scenario.protocol) if validate else None
    target = (_targets_from_scenario(scenario) or [None])[0]
    before = None
    if plugin is not None and target:
        before = harness.probe(plugin, target, _scenario_port(scenario))
        log_lines.append(f"[probe-antes] responsive={before.responsive} {before.detail}")

    capture = subprocess.Popen(
        shlex.split(_tcpdump_command(scenario)),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    log.info("Captura iniciada (pid=%s) -> %s", capture.pid, scenario.output_pcap)
    time.sleep(1.0)  # deixa o tcpdump subir antes do trafego

    status = "done"
    try:
        if scenario.normal_traffic_command:
            log_lines.append(f"[normal] {scenario.normal_traffic_command}")
            _run_traffic(scenario.normal_traffic_command, scenario.duration_seconds, log_lines)
        if scenario.attack_command:
            log_lines.append(f"[attack] {scenario.attack_command}")
            _run_traffic(scenario.attack_command, scenario.duration_seconds, log_lines)
    except Exception as exc:  # noqa: BLE001 - registra e segue para encerrar captura
        status = "failed"
        log_lines.append(f"ERRO: {exc}")
        log.error("Falha na execucao do cenario: %s", exc)
    finally:
        time.sleep(1.0)
        capture.terminate()
        try:
            capture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            capture.kill()
        log.info("Captura encerrada.")

    record = RunRecord(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        vuln_id=vuln_id,
        started_at=started,
        status=status,
        log_path=str(log_path),
        pcap_path=scenario.output_pcap,
        llm_model=settings.llm_model if settings.llm_provider != "offline" else "offline",
        llm_seed=str(settings.llm_seed),
    )

    # Sonda DEPOIS + veredito de efeito.
    if plugin is not None and target:
        after = harness.probe(plugin, target, _scenario_port(scenario))
        log_lines.append(f"[probe-depois] responsive={after.responsive} {after.detail}")
        report = harness.build_report(before, after, scenario.output_pcap, target)
        record.effect_verdict = report.verdict
        record.responsive_before = _bool_str(report.responsive_before)
        record.responsive_after = _bool_str(report.responsive_after)
        record.anomalies = "; ".join(report.anomalies)
        log_lines.append(f"[veredito] {report.verdict} anomalias={report.anomalies}")

    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    return record


def _scenario_port(scenario: Scenario) -> int | None:
    """Extrai a porta --port do comando de ataque (ou do plugin)."""
    for cmd in (scenario.attack_command, scenario.normal_traffic_command):
        parts = cmd.split()
        for i, tok in enumerate(parts):
            if tok == "--port" and i + 1 < len(parts):
                try:
                    return int(parts[i + 1])
                except ValueError:
                    pass
    return None


def _bool_str(value: bool | None) -> str:
    return "yes" if value is True else "no" if value is False else "unknown"


def _run_traffic(command: str, duration: int, log_lines: list[str]) -> None:
    """Executa um comando de trafego com timeout = duracao do cenario."""
    try:
        proc = subprocess.run(
            shlex.split(command),
            timeout=duration + 5,
            capture_output=True, text=True,
        )
        if proc.stdout:
            log_lines.append(proc.stdout.strip())
        if proc.returncode != 0 and proc.stderr:
            log_lines.append(f"stderr: {proc.stderr.strip()}")
    except subprocess.TimeoutExpired:
        log_lines.append(f"timeout apos {duration + 5}s: {command}")


def run_scenario(
    scenario: Scenario,
    dry_run: bool = True,
    execute: bool = False,
    assume_yes: bool = False,
    vuln_id: str = "",
    persist: bool = True,
    validate: bool = False,
) -> RunRecord:
    """Ponto de entrada do runner. Default = dry-run (seguro).

    Para executar de verdade: execute=True e assume_yes=True.
    validate=True roda o harness de efeito (sonda antes/depois + analise de PCAP).
    """
    run_id = _new_run_id()

    if not execute or dry_run:
        record = _dry_run(scenario, run_id)
    else:
        if not assume_yes:
            raise PermissionError(
                "Execucao real requer confirmacao explicita (assume_yes=True / flag --yes)."
            )
        record = _execute(scenario, run_id, vuln_id=vuln_id, validate=validate)

    if persist:
        conn = get_connection()
        try:
            repository.save_run(conn, record, scenario_yaml=scenario.model_dump_json())
        finally:
            conn.close()
    return record
