#!/usr/bin/env bash
set -euo pipefail

export VULNFORGE_LLM_PROVIDER=offline
export VULNFORGE_DATA_DIR="${VULNFORGE_DATA_DIR:-data}"
export VULNFORGE_DB_PATH="${VULNFORGE_DB_PATH:-$VULNFORGE_DATA_DIR/vulnforge.db}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

mkdir -p "$VULNFORGE_DATA_DIR/input" "$VULNFORGE_DATA_DIR/datasets" scenarios reports
"$PYTHON_BIN" -m vulnforge.cli import-vulns --file examples/vulnerabilities.json
"$PYTHON_BIN" -m vulnforge.cli analyze --vuln-id CVE-DEMO-0001
"$PYTHON_BIN" -m vulnforge.cli generate-scenario --vuln-id CVE-DEMO-0001 --native --out scenarios/minimal.yaml
"$PYTHON_BIN" -m vulnforge.cli run-scenario --file scenarios/minimal.yaml --vuln-id CVE-DEMO-0001
"$PYTHON_BIN" -m vulnforge.cli build-dataset --flows examples/flows.csv --label normal --out "$VULNFORGE_DATA_DIR/datasets/normal.csv"
"$PYTHON_BIN" -m vulnforge.cli build-dataset --flows examples/flows_attack.csv --label xrce_dds_flooding --out "$VULNFORGE_DATA_DIR/datasets/attack.csv"
"$PYTHON_BIN" -c "from vulnforge.dataset.builder import merge_datasets; merge_datasets(['$VULNFORGE_DATA_DIR/datasets/normal.csv','$VULNFORGE_DATA_DIR/datasets/attack.csv'],'$VULNFORGE_DATA_DIR/datasets/demo.csv')"
"$PYTHON_BIN" -m vulnforge.cli train-ids --dataset "$VULNFORGE_DATA_DIR/datasets/demo.csv"
RUN_ID="$("$PYTHON_BIN" -c "import sqlite3; c=sqlite3.connect('$VULNFORGE_DB_PATH'); print(c.execute('select run_id from runs order by started_at desc limit 1').fetchone()[0])")"
"$PYTHON_BIN" -m vulnforge.cli report --run-id "$RUN_ID"
echo "Minimal pipeline complete: reports/$RUN_ID.md"
