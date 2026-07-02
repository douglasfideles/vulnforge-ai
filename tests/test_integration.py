import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest
from typer.testing import CliRunner

from vulnforge.cli import app
from vulnforge.config import Settings
from vulnforge.llm.analyzer import analyze
from vulnforge.models import AttackType, RunRecord, Scenario, ThreatAnalysis, Vulnerability
from vulnforge.reports import generator as report_generator
from vulnforge.scenarios.generator import generate_scenario
from vulnforge.traffic import runner as scenario_runner
from vulnforge.traffic.docker_gen import generate_bundle


def test_cli_help_and_offline_analysis():
    runner = CliRunner()
    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    assert "run-scenario" in help_result.stdout
    result = runner.invoke(
        app,
        ["analyze", "--text", "XRCE agent resource exhaustion denial of service", "--provider", "offline"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["likely_attack_type"] == "flooding"
    assert payload["source"] == "rules"


def test_llm_failure_falls_back_to_rules(monkeypatch):
    def fail(*args, **kwargs):
        raise TimeoutError("offline")
    monkeypatch.setattr("vulnforge.llm.analyzer.requests.post", fail)
    settings = Settings(llm_provider="local", llm_base_url="http://127.0.0.1:1", llm_model="test")
    result = analyze("Zenoh keepalive flood", settings=settings)
    assert result.source == "rules"
    assert result.likely_attack_type == AttackType.flooding


def test_runner_dry_run_persists_without_execution(monkeypatch, capsys):
    saved = {}
    monkeypatch.setattr(scenario_runner, "save_run", lambda record, yaml: saved.update(record=record, yaml=yaml))
    scenario = generate_scenario(
        ThreatAnalysis(protocol="DDS", likely_attack_type=AttackType.flooding, dataset_label="dds_flooding"),
        native=True,
    )
    record = scenario_runner.run_scenario(scenario)
    assert record.status == "dry-run"
    assert saved["record"].run_id == record.run_id
    output = capsys.readouterr().out
    commands = [line for line in output.splitlines() if line.startswith("$ ")]
    assert commands[0].startswith("$ tcpdump")
    assert "attacks.flooding" in commands[1]


@pytest.mark.parametrize(
    ("execute", "confirmed", "message"),
    [(False, False, "--execute"), (True, False, "confirmation")],
)
def test_runner_real_execution_gates(monkeypatch, execute, confirmed, message):
    monkeypatch.setattr(scenario_runner, "save_run", lambda *args: None)
    scenario = Scenario(
        scenario_id="safe", protocol="DDS", attack_type=AttackType.normal,
        output_pcap="x.pcap", label="normal",
    )
    with pytest.raises(ValueError, match=message):
        scenario_runner.run_scenario(scenario, dry_run=False, execute=execute, confirmed=confirmed)


def test_ids_training_and_persistence(tmp_path, monkeypatch):
    from vulnforge.ids import trainer

    normal = pd.DataFrame({"packets": range(1, 21), "bytes": range(10, 30), "label": "normal"})
    attack = pd.DataFrame({"packets": range(100, 120), "bytes": range(1000, 1020), "label": "attack"})
    dataset = tmp_path / "flows.csv"
    pd.concat([normal, attack], ignore_index=True).to_csv(dataset, index=False)
    monkeypatch.setattr(trainer, "get_settings", lambda: SimpleNamespace(models_dir=tmp_path / "models"))
    result = trainer.train(dataset)
    assert result["best_model"] == "RandomForest"
    assert all(item["f1"] == 1.0 for item in result["metrics"])
    assert Path(result["model_path"]).is_file()
    assert Path(result["report_path"]).is_file()


def test_report_joins_run_vulnerability_and_analysis(tmp_path, monkeypatch):
    run = {
        **RunRecord(run_id="run-1", scenario_id="s", vuln_id="CVE-1", started_at="now", status="dry-run").model_dump(),
        "scenario_yaml": "scenario_id: s\nprotocol: DDS\nattack_type: flooding\nduration_seconds: 10\noutput_pcap: x\nlabel: dds_flooding\n",
    }
    monkeypatch.setattr(report_generator, "get_run", lambda run_id: run.copy())
    monkeypatch.setattr(report_generator, "get_vuln", lambda vuln_id: Vulnerability(id=vuln_id, title="Demo", description="Description"))
    monkeypatch.setattr(report_generator, "get_analysis", lambda vuln_id: ThreatAnalysis(protocol="DDS"))
    output = report_generator.build_report("run-1", tmp_path / "report.md")
    text = output.read_text()
    assert "CVE-1" in text
    assert "Threat analysis" in text
    assert "dry-run" in text


def test_cicflowmeter_missing_has_actionable_error(tmp_path, monkeypatch):
    from vulnforge.dataset import builder
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"pcap")
    monkeypatch.setattr(builder.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="CICFlowMeter"):
        builder.build_dataset(pcap, "attack", tmp_path / "out.csv")


def test_generated_docker_bundle_has_reproducible_context(tmp_path):
    target = generate_bundle(
        "flooding", Path("-m vulnforge.traffic.attacks.flooding"), tmp_path / "docker/attacks"
    )
    dockerfile = (target / "Dockerfile").read_text()
    compose = (target / "docker-compose.yml").read_text()
    assert 'ENTRYPOINT ["python", "-m", "vulnforge.traffic.attacks.flooding"]' in dockerfile
    assert "version:" not in compose
    assert "context: ../../.." in compose


def test_citation_metadata_is_valid_yaml():
    import yaml
    payload = yaml.safe_load(Path("CITATION.cff").read_text())
    assert payload["cff-version"] == "1.2.0"
    assert payload["license"] == "GPL-3.0-or-later"


def test_root_container_configuration_uses_relative_artifact_volumes():
    import yaml
    compose = yaml.safe_load(Path("docker-compose.yml").read_text())
    assert "version" not in compose
    service = compose["services"]["vulnforge"]
    assert service["build"] == "."
    assert service["volumes"] == [
        "./data:/app/data", "./scenarios:/app/scenarios", "./reports:/app/reports"
    ]
    dockerfile = Path("Dockerfile").read_text()
    assert "python:3.11-slim" in dockerfile
    assert 'CMD ["bash", "scripts/run-minimal.sh"]' in dockerfile
    assert "cuda" not in dockerfile.lower()
