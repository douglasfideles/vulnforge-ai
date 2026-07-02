#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# VulnForge AI - Minimal offline smoke test.
# No network, GPU, LLM key, tcpdump, or Docker required.
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Prefer installed protoforge, otherwise python -m.
if command -v protoforge >/dev/null 2>&1; then
  PF=(protoforge)
elif [ -x ".venv/bin/protoforge" ]; then
  PF=(.venv/bin/protoforge)
else
  PF=(python -m vulnforge.cli)
fi

step() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

rm -f data/vulnforge.db

step "1/7  Import vulnerabilities"
"${PF[@]}" import-vulns --file data/raw/vulns.json

step "2/7  Analyze CVE (rule-based offline)"
"${PF[@]}" analyze --vuln-id CVE-2024-0001 --protocol XRCE-DDS

step "3/7  Generate scenario YAML"
"${PF[@]}" generate-scenario --vuln-id CVE-2024-0001 --out scenarios/generated/cve_0001.yaml

step "4/7  Run scenario (DRY-RUN)"
RUN_OUT=$("${PF[@]}" run-scenario --file scenarios/generated/cve_0001.yaml --dry-run)
echo "$RUN_OUT"
RUN_ID=$(printf '%s\n' "$RUN_OUT" | sed -n 's/.*run_id=\([^ ]*\).*/\1/p' | tail -1)

step "5/7  Build labeled dataset"
"${PF[@]}" build-dataset --flows data/flows/example.csv --label flooding --out data/datasets/out.csv

step "6/7  Train IDS baseline"
"${PF[@]}" train-ids --dataset data/datasets/example_labeled.csv --label-column label

step "7/7  Generate report"
if [ -n "${RUN_ID:-}" ]; then
  "${PF[@]}" report --run-id "$RUN_ID"
else
  echo "WARNING: run_id not captured; skipping report." >&2
fi

printf '\n\033[1;32mMINIMAL TEST PASSED.\033[0m\n'
echo "  - scenario:   scenarios/generated/cve_0001.yaml"
echo "  - dataset:    data/datasets/out.csv"
echo "  - model:      data/models/example_labeled_RandomForest.joblib"
[ -n "${RUN_ID:-}" ] && echo "  - report:     reports/${RUN_ID}.md"
