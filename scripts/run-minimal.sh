#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# VulnForge AI - TESTE MINIMO (SeloF)
#
# Executa o pipeline COMPLETO em modo OFFLINE e SEGURO:
#   vuln -> analise (rule-based) -> cenario -> run (DRY-RUN) -> dataset -> IDS -> relatorio
#
# NAO precisa de: rede, GPU, chave de LLM, tcpdump, Docker ou alvos externos.
# Toda a execucao e dry-run (nenhum trafego de ataque real e enviado).
#
# Uso:   bash scripts/run-minimal.sh
# ---------------------------------------------------------------------------
set -euo pipefail

# Sempre rodar a partir da raiz do repositorio (independe de onde for chamado).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Resolve o comando do CLI: entrypoint `protoforge`, ou fallback `python -m`.
if command -v protoforge >/dev/null 2>&1; then
  PF=(protoforge)
elif [ -x ".venv/bin/protoforge" ]; then
  PF=(.venv/bin/protoforge)
else
  PF=(python -m vulnforge.cli)
fi

step() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

step "1/7  Importar vulnerabilidades (JSON -> SQLite)"
"${PF[@]}" import-vulns --file data/raw/vulns.json

step "2/7  Analisar CVE (rule-based offline)"
"${PF[@]}" analyze --vuln-id CVE-2024-0001 --protocol XRCE-DDS

step "3/7  Gerar cenario YAML"
"${PF[@]}" generate-scenario --vuln-id CVE-2024-0001 --out scenarios/generated/cve_0001.yaml

step "4/7  Executar cenario (DRY-RUN: apenas imprime comandos)"
# Captura o run_id (persistido mesmo em dry-run) para alimentar o relatorio.
RUN_OUT="$("${PF[@]}" run-scenario --file scenarios/examples/xrce_dds_flooding.yaml --dry-run)"
echo "$RUN_OUT"
RUN_ID="$(printf '%s\n' "$RUN_OUT" | sed -n 's/.*run_id=\([^ ]*\).*/\1/p' | tail -1)"

step "5/7  Construir dataset rotulado (CSV de flows)"
"${PF[@]}" build-dataset --flows data/flows/example.csv --label flooding --out data/datasets/out.csv

step "6/7  Treinar IDS baseline (RandomForest + LogisticRegression)"
"${PF[@]}" train-ids --dataset data/datasets/example_labeled.csv --label-column label

step "7/7  Gerar relatorio Markdown end-to-end"
if [ -n "${RUN_ID:-}" ]; then
  "${PF[@]}" report --run-id "$RUN_ID"
else
  echo "AVISO: run_id nao capturado; pulei o relatorio." >&2
fi

printf '\n\033[1;32mTESTE MINIMO CONCLUIDO COM SUCESSO.\033[0m\n'
echo "  - cenario:   scenarios/generated/cve_0001.yaml"
echo "  - dataset:   data/datasets/out.csv"
echo "  - modelo:    data/models/example_labeled_RandomForest.joblib"
[ -n "${RUN_ID:-}" ] && echo "  - relatorio: reports/${RUN_ID}.md"
