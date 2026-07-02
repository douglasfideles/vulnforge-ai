from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from vulnforge.config import get_settings
from vulnforge.db import save_run
from vulnforge.models import RunRecord, Scenario
from vulnforge.protocols.registry import get as get_plugin
from vulnforge.traffic.safety import resolve_safe_target
from vulnforge.validation.harness import decide_verdict
from vulnforge.validation.pcap_analysis import analyze_pcap

log = logging.getLogger(__name__)


def _run_id() -> str:
    return "run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


def _arguments(command: str) -> list[str]:
    return shlex.split(command)


def _option(command: str, name: str) -> str | None:
    args = _arguments(command)
    try:
        return args[args.index(name) + 1]
    except (ValueError, IndexError):
        return None


def _persist(record: RunRecord, scenario: Scenario) -> RunRecord:
    save_run(record, yaml.safe_dump(scenario.model_dump(mode="json"), sort_keys=False))
    return record


def run_scenario(
    scenario: Scenario, *, dry_run: bool = True, execute: bool = False,
    confirmed: bool = False, validate: bool = False, vuln_id: str = "",
) -> RunRecord:
    cfg = get_settings()
    run_id = _run_id()
    started = datetime.now(timezone.utc).isoformat()
    pcap = Path(scenario.output_pcap)
    log_path = cfg.runs_dir / f"{run_id}.log"
    capture = ["tcpdump", "-i", scenario.capture_interface, "-w", str(pcap)]
    commands = [command for command in (scenario.normal_traffic_command, scenario.attack_command) if command]
    if dry_run:
        print(f"Scenario: {scenario.scenario_id}\nRun: {run_id}\nPCAP: {pcap}\nInterface: {scenario.capture_interface}\nDuration: {scenario.duration_seconds}\nLabel: {scenario.label}")
        print("$ " + shlex.join(capture))
        for command in commands:
            print("$ " + command)
        return _persist(RunRecord(
            run_id=run_id, scenario_id=scenario.scenario_id, vuln_id=vuln_id,
            started_at=started, status="dry-run", pcap_path=str(pcap),
            llm_model=cfg.llm_model if cfg.llm_provider != "offline" else "offline",
            llm_seed=str(cfg.llm_seed),
        ), scenario)
    if not execute:
        raise ValueError("Real execution requires --no-dry-run and --execute")
    if not confirmed:
        raise ValueError("Real execution requires explicit confirmation (--yes)")
    targets = [_option(command, "--target") for command in commands]
    for target in (target for target in targets if target):
        resolve_safe_target(target)
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        raise RuntimeError("tcpdump is required for real execution; install it and ensure it is on PATH")
    pcap.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    plugin = get_plugin(scenario.protocol)
    target = next((item for item in reversed(targets) if item), "127.0.0.1")
    port = int(_option(scenario.attack_command, "--port") or _option(scenario.normal_traffic_command, "--port") or (plugin.default_port if plugin else 0))
    before = plugin.health_probe(target, port) if validate and plugin else None
    status = "done"
    capture_process = None
    with log_path.open("w", encoding="utf-8") as output:
        try:
            capture_process = subprocess.Popen([tcpdump, *capture[1:]], stdout=output, stderr=subprocess.STDOUT)
            time.sleep(1)
            for command in commands:
                output.write(f"$ {command}\n")
                output.flush()
                subprocess.run(
                    _arguments(command), stdout=output, stderr=subprocess.STDOUT,
                    timeout=scenario.duration_seconds + 5, check=True,
                )
        except Exception as exc:
            status = "failed"
            output.write(f"ERROR: {exc}\n")
            log.exception("Scenario execution failed")
        finally:
            if capture_process:
                capture_process.terminate()
                try:
                    capture_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    capture_process.kill()
    after = plugin.health_probe(target, port) if validate and plugin else None
    report = decide_verdict(before, after, analyze_pcap(pcap, target)) if validate else None
    record = RunRecord(
        run_id=run_id, scenario_id=scenario.scenario_id, vuln_id=vuln_id,
        started_at=started, status=status, log_path=str(log_path), pcap_path=str(pcap),
        effect_verdict=report.verdict if report else "not_validated",
        responsive_before=("yes" if report and report.responsive_before else "no") if report and report.responsive_before is not None else "",
        responsive_after=("yes" if report and report.responsive_after else "no") if report and report.responsive_after is not None else "",
        anomalies="; ".join(report.anomalies) if report else "",
        llm_model=cfg.llm_model if cfg.llm_provider != "offline" else "offline",
        llm_seed=str(cfg.llm_seed),
    )
    return _persist(record, scenario)

