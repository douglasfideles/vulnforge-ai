#!/usr/bin/env python3
"""Reproduce and verify the artifact's principal offline claims."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def _safe_reset(path: Path) -> None:
    resolved = path.resolve()
    repository = Path.cwd().resolve()
    if resolved in (repository, repository.parent, Path("/")) or len(resolved.parts) < 3:
        raise RuntimeError(f"Refusing unsafe reproduction output path: {resolved}")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("results/reproduction"))
    args = parser.parse_args()
    output = args.out.resolve()
    _safe_reset(output)

    os.environ["VULNFORGE_LLM_PROVIDER"] = "offline"
    os.environ["VULNFORGE_DATA_DIR"] = str(output / "data")
    os.environ["VULNFORGE_DB_PATH"] = str(output / "data" / "vulnforge.db")

    # Imports intentionally follow environment setup so the settings singleton is isolated.
    from vulnforge.config import get_settings
    from vulnforge.dataset.builder import build_dataset, merge_datasets
    from vulnforge.db import save_analysis, upsert_vuln
    from vulnforge.ids.trainer import train
    from vulnforge.llm.analyzer import analyze
    from vulnforge.protocols.registry import get as get_plugin
    from vulnforge.reports.generator import build_report
    from vulnforge.scenarios.generator import generate_scenario, load_scenario, save_scenario
    from vulnforge.traffic.codegen import CodeValidationError, validate_mutator
    from vulnforge.traffic.runner import run_scenario
    from vulnforge.traffic.safety import UnsafeTargetError, resolve_safe_target
    from vulnforge.vulnerability.normalizer import import_file

    get_settings.cache_clear()
    commands = [
        "protoforge import-vulns --file examples/vulnerabilities.json",
        "protoforge analyze --vuln-id CVE-DEMO-0001 --provider offline",
        "protoforge generate-scenario --vuln-id CVE-DEMO-0001 --native --out scenario.yaml",
        "protoforge run-scenario --file scenario.yaml",
        "protoforge build-dataset (normal and attack flows)",
        "merge_datasets(normal.csv, attack.csv)",
        "protoforge train-ids --dataset demo.csv",
        "protoforge report --run-id <generated>",
    ]

    vulnerabilities = import_file("examples/vulnerabilities.json")
    for vulnerability in vulnerabilities:
        upsert_vuln(vulnerability)
    vulnerability = vulnerabilities[0]
    analysis = analyze(f"{vulnerability.title}\n{vulnerability.description}", settings=get_settings())
    save_analysis(vulnerability.id, analysis)

    scenario = generate_scenario(analysis, native=True)
    scenario.output_pcap = str(output / "data" / "runs" / "minimal.pcap")
    scenario_path = save_scenario(scenario, output / "scenario.yaml")
    scenario_round_trip = load_scenario(scenario_path) == scenario
    run = run_scenario(scenario, vuln_id=vulnerability.id)

    datasets = output / "data" / "datasets"
    normal = datasets / "normal.csv"
    attack = datasets / "attack.csv"
    combined = datasets / "demo.csv"
    build_dataset("examples/flows.csv", "normal", normal)
    build_dataset("examples/flows_attack.csv", "xrce_dds_flooding", attack)
    dataset_meta = merge_datasets([normal, attack], combined)
    training = train(combined)
    report_path = build_report(run.run_id, output / "reports" / f"{run.run_id}.md")

    safety_public_rejected = False
    try:
        resolve_safe_target("8.8.8.8")
    except UnsafeTargetError:
        safety_public_rejected = True

    unsafe_code_rejected = False
    try:
        validate_mutator("import os\nreturn baseline")
    except CodeValidationError:
        unsafe_code_rejected = True

    plugins = {
        name: {
            "port": get_plugin(name).default_port,
            "transport": get_plugin(name).transport,
            "magic_ok": (
                b"XRCE" in get_plugin(name).baseline_message(1)
                if name == "XRCE-DDS"
                else get_plugin(name).baseline_message(1).startswith(b"RTPS")
                if name == "DDS"
                else bool(get_plugin(name).baseline_message(1))
            ),
        }
        for name in ("XRCE-DDS", "Zenoh", "DDS")
    }
    metrics = {item["model"]: item for item in training["metrics"]}
    checks = {
        "analysis_protocol": analysis.protocol == "XRCE-DDS",
        "analysis_attack": analysis.likely_attack_type.value == "flooding",
        "analysis_label": analysis.dataset_label == "xrce_dds_flooding",
        "analysis_source": analysis.source == "rules",
        "analysis_confidence": analysis.confidence == 0.6,
        "scenario_round_trip": scenario_round_trip,
        "dry_run_status": run.status == "dry-run",
        "dataset_rows": dataset_meta.rows == 24,
        "best_model": training["best_model"] == "RandomForest",
        "random_forest_f1": metrics["RandomForest"]["f1"] == 1.0,
        "logistic_regression_f1": metrics["LogisticRegression"]["f1"] == 1.0,
        "model_exists": Path(training["model_path"]).is_file(),
        "report_exists": report_path.is_file(),
        "safety_public_rejected": safety_public_rejected,
        "unsafe_code_rejected": unsafe_code_rejected,
        "protocol_framing": all(item["magic_ok"] for item in plugins.values()),
    }
    passed = all(checks.values())
    summary = {
        "artifact": "VulnForge AI",
        "artifact_version": "1.0.0",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "llm_provider": "offline",
            "seed": get_settings().llm_seed,
        },
        "pipeline_status": "passed" if passed else "failed",
        "analysis": analysis.model_dump(mode="json"),
        "run_id": run.run_id,
        "dry_run_status": run.status,
        "dataset_rows": dataset_meta.rows,
        "best_model": training["best_model"],
        "metrics": training["metrics"],
        "plugins": plugins,
        "checks": checks,
        "artifacts": {
            "scenario": str(scenario_path.relative_to(output)),
            "dataset": str(combined.relative_to(output)),
            "model": str(Path(training["model_path"]).relative_to(output)),
            "ids_report": str(Path(training["report_path"]).relative_to(output)),
            "run_report": str(report_path.relative_to(output)),
        },
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output / "commands.log").write_text("\n".join(f"$ {command}" for command in commands) + "\n", encoding="utf-8")
    rows = "\n".join(f"| `{name}` | {'PASS' if value else 'FAIL'} |" for name, value in checks.items())
    (output / "summary.md").write_text(
        "# VulnForge AI — reprodução\n\n"
        f"- Estado: **{'PASS' if passed else 'FAIL'}**\n"
        f"- Execução: `{run.run_id}` (`{run.status}`)\n"
        f"- Melhor modelo: **{training['best_model']}**\n"
        f"- F1 RandomForest: `{metrics['RandomForest']['f1']:.2f}`\n"
        f"- F1 LogisticRegression: `{metrics['LogisticRegression']['f1']:.2f}`\n\n"
        "| Verificação | Resultado |\n|---|---|\n" + rows + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2))
    print(f"\nReproduction {'PASSED' if passed else 'FAILED'}: {output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
