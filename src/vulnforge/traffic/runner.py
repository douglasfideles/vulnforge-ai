"""Scenario runner: dry-run and real execution with capture."""

from __future__ import annotations

import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..db import get_connection
from ..logging_setup import get_logger
from ..models import RunRecord, Scenario
from ..protocols import registry
from ..validation.harness import run_validation
from .safety import UnsafeTargetError, validate_target

logger = get_logger(__name__)


def _targets_from_command(cmd: str) -> list[str]:
    parts = shlex.split(cmd)
    targets: list[str] = []
    for i, part in enumerate(parts):
        if part == "--target" and i + 1 < len(parts):
            targets.append(parts[i + 1])
    return targets


def _port_from_command(cmd: str, default: int) -> int:
    parts = shlex.split(cmd)
    for i, part in enumerate(parts):
        if part == "--port" and i + 1 < len(parts):
            try:
                return int(parts[i + 1])
            except ValueError:
                return default
    return default


def _run_id() -> str:
    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"run-{now}-{uuid.uuid4().hex[:6]}"


def _log(msg: str) -> str:
    timestamp = datetime.now(timezone.utc).isoformat()
    return f"[{timestamp}] {msg}"


def _print_plan(scenario: Scenario, run_id: str) -> None:
    print(f"Scenario: {scenario.scenario_id}")
    print(f"run_id: {run_id}")
    print(f"pcap: {scenario.output_pcap}")
    print(f"interface: {scenario.capture_interface}")
    print(f"duration: {scenario.duration_seconds}s")
    print(f"label: {scenario.label}")
    print("Commands that would run:")
    print(f"$ tcpdump -i {scenario.capture_interface} -w {scenario.output_pcap}")
    if scenario.normal_traffic_command:
        print(f"$ {scenario.normal_traffic_command}")
    if scenario.attack_command:
        print(f"$ {scenario.attack_command}")


def _ensure_dirs(paths: list[str | Path]) -> None:
    for p in paths:
        Path(p).parent.mkdir(parents=True, exist_ok=True)


def _execute_command(
    cmd: str,
    timeout: float,
    log_file: Path,
) -> subprocess.CompletedProcess[Any] | None:
    if not cmd:
        return None
    logger.info("Executando: %s", cmd)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(_log(f"$ {cmd}\n"))
        proc = subprocess.Popen(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            stdout, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
            fh.write(_log("TIMEOUT\n"))
        fh.write(stdout or "")
        fh.write(_log(f"exit_code={proc.returncode}\n"))
        return subprocess.CompletedProcess(args=cmd, returncode=proc.returncode, stdout=stdout)


def run_scenario(
    scenario: Scenario,
    dry_run: bool = True,
    execute: bool = False,
    assume_yes: bool = False,
    vuln_id: str = "",
    validate: bool = False,
) -> RunRecord:
    """Run (or dry-run) a scenario and persist a RunRecord."""
    run_id = _run_id()
    started_at = datetime.now(timezone.utc).isoformat()
    record = RunRecord(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        vuln_id=vuln_id,
        started_at=started_at,
    )

    if dry_run or not execute:
        _print_plan(scenario, run_id)
        record.status = "dry-run"
        conn = get_connection()
        try:
            from ..scenarios.schema import dump_scenario
            yaml_path = Path("data/runs") / f"{run_id}.yaml"
            dump_scenario(scenario, yaml_path)
            from ..vulnerability.repository import save_run
            save_run(conn, record, scenario_yaml=yaml_path.read_text(encoding="utf-8"))
        finally:
            conn.close()
        return record

    # Real execution path
    targets = _targets_from_command(scenario.normal_traffic_command) + _targets_from_command(scenario.attack_command)
    for target in targets:
        try:
            validate_target(target)
        except UnsafeTargetError as exc:
            raise UnsafeTargetError(f"Cenario abortado: {exc}") from exc

    tcpdump_path = _which("tcpdump")
    if not tcpdump_path:
        raise RuntimeError("tcpdump nao encontrado no PATH")

    _ensure_dirs([scenario.output_pcap, f"data/runs/{run_id}.log"])
    log_path = Path("data/runs") / f"{run_id}.log"
    pcap_path = Path(scenario.output_pcap)

    record.status = "running"
    capture_proc: subprocess.Popen[Any] | None = None
    try:
        capture_cmd = [tcpdump_path, "-i", scenario.capture_interface, "-w", str(pcap_path)]
        capture_proc = subprocess.Popen(capture_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)

        timeout = scenario.duration_seconds + 5
        _execute_command(scenario.normal_traffic_command, timeout, log_path)
        _execute_command(scenario.attack_command, timeout, log_path)

        record.status = "done"
    except Exception as exc:  # noqa: BLE001
        logger.exception("Erro durante execucao do cenario")
        record.status = "failed"
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(_log(f"ERRO: {exc}\n"))
    finally:
        if capture_proc is not None:
            capture_proc.terminate()
            try:
                capture_proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                capture_proc.kill()
                capture_proc.wait()

    record.log_path = str(log_path)
    record.pcap_path = str(pcap_path)

    if validate:
        try:
            plugin_cls = registry.get(scenario.protocol)
            plugin = plugin_cls()
        except (KeyError, Exception):
            plugin = None
        port = _port_from_command(scenario.attack_command, _port_from_command(scenario.normal_traffic_command, 0))
        target = targets[0] if targets else "127.0.0.1"
        report = run_validation(plugin, target, pcap_path, port=port if port else None)
        record.effect_verdict = report.verdict
        record.responsive_before = "yes" if report.responsive_before else "no"
        record.responsive_after = "yes" if report.responsive_after else "no"
        record.anomalies = "; ".join(report.anomalies)

    conn = get_connection()
    try:
        from ..vulnerability.repository import save_run
        from ..scenarios.schema import dump_scenario
        yaml_path = Path("data/runs") / f"{run_id}.yaml"
        dump_scenario(scenario, yaml_path)
        save_run(conn, record, scenario_yaml=yaml_path.read_text(encoding="utf-8"))
    finally:
        conn.close()

    return record


def _which(name: str) -> str | None:
    import shutil
    return shutil.which(name)
