#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# VulnForge AI - Reprodução automatizada das principais reivindicações.
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

if command -v protoforge >/dev/null 2>&1; then
  PF=(protoforge)
elif [ -x ".venv/bin/protoforge" ]; then
  PF=(.venv/bin/protoforge)
else
  PF=(python -m vulnforge.cli)
fi

step() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

rm -f data/vulnforge.db
mkdir -p scenarios/generated data/datasets data/models reports

step "Reivindicacao #1: Analise rule-based identifica flooding em XRCE-DDS"
"${PF[@]}" analyze --text "XRCE-DDS agent resource exhaustion via UDP flood" --protocol XRCE-DDS

step "Reivindicacao #2: Geracao de cenario a partir de CVE importado"
"${PF[@]}" import-vulns --file data/raw/vulns.json
"${PF[@]}" generate-scenario --vuln-id CVE-2024-0001 --out scenarios/generated/cve_0001.yaml

step "Reivindicacao #3: Dry-run seguro do cenario"
RUN_OUT=$("${PF[@]}" run-scenario --file scenarios/generated/cve_0001.yaml --dry-run)
echo "$RUN_OUT"
RUN_ID=$(printf '%s\n' "$RUN_OUT" | sed -n 's/.*run_id=\([^ ]*\).*/\1/p' | tail -1)

step "Reivindicacao #4: Sandbox AST rejeita mutadores maliciosos"
.venv/bin/pytest tests/test_codegen_sandbox.py -q

step "Reivindicacao #5: Dataset rotulado e treinamento IDS baseline"
"${PF[@]}" build-dataset --flows data/flows/example.csv --label flooding --out data/datasets/out.csv
"${PF[@]}" train-ids --dataset data/datasets/example_labeled.csv --label-column label

step "Reivindicacao #6: Relatorio end-to-end a partir do run_id"
if [ -n "${RUN_ID:-}" ]; then
  "${PF[@]}" report --run-id "$RUN_ID"
else
  echo "AVISO: run_id nao capturado." >&2
fi

printf '\n\033[1;32mEXPERIMENTOS REPRODUZIDOS COM SUCESSO.\033[0m\n'
