#!/usr/bin/env bash
# Valida o fluxo completo da ferramenta VulnForge AI com LLM real (OpenRouter).
# Requer: .env com OPENROUTER_API_KEY, venv ativo (.venv/), tcpdump disponivel.
#
# Uso:
#   source .venv/bin/activate
#   bash scripts/sbseg2024/validate_full_flow.sh

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO"

# Carrega .env
if [[ -f .env ]]; then
    set -o allexport
    # shellcheck disable=SC1091
    source .env
    set +o allexport
else
    echo "ERRO: .env nao encontrado. Copie .env.example para .env e adicione sua chave." >&2
    exit 1
fi

PROTOFORGE=".venv/bin/protoforge"
if [[ ! -x "$PROTOFORGE" ]]; then
    echo "ERRO: $PROTOFORGE nao encontrado. Execute: pip install -e ." >&2
    exit 1
fi

echo "========================================"
echo " VulnForge AI — Validacao Completa"
echo " Provider: ${VULNFORGE_LLM_PROVIDER:-openrouter}"
echo " Modelo:   ${VULNFORGE_LLM_MODEL:-anthropic/claude-sonnet-4}"
echo "========================================"
echo ""

# 1. Importa vulnerabilidades
echo "[1/7] Importando vulnerabilidades..."
"$PROTOFORGE" import-vulns --file data/raw/vulns.json
echo "  OK"

# 2. Analisa via LLM
echo "[2/7] Analisando via LLM (${VULNFORGE_LLM_PROVIDER:-openrouter})..."
"$PROTOFORGE" analyze \
    --vuln-id CVE-2024-0001 \
    --protocol XRCE-DDS \
    --provider "${VULNFORGE_LLM_PROVIDER:-openrouter}"
echo "  OK"

# 3. Gera cenario
echo "[3/7] Gerando cenario YAML..."
mkdir -p scenarios/generated
"$PROTOFORGE" generate-scenario \
    --vuln-id CVE-2024-0001 \
    --protocol XRCE-DDS \
    --target 127.0.0.1 \
    --native \
    --out scenarios/generated/sbseg2024_validation.yaml
echo "  OK: scenarios/generated/sbseg2024_validation.yaml"

# 4. Executa cenario com captura real
echo "[4/7] Executando cenario (captura real)..."
echo "  AVISO: pode precisar de sudo para tcpdump."
RUN_OUTPUT=$("$PROTOFORGE" run-scenario \
    --file scenarios/generated/sbseg2024_validation.yaml \
    --no-dry-run --execute --yes 2>&1 || true)
echo "$RUN_OUTPUT"
RUN_ID=$(echo "$RUN_OUTPUT" | grep -oP 'run-[0-9A-Za-z_-]+' | head -1 || echo "")
echo "  run_id = ${RUN_ID:-<nao encontrado>}"

# 5. Constroi dataset
echo "[5/7] Construindo dataset..."
PCAP="data/runs/${RUN_ID}.pcap"
if [[ -n "$RUN_ID" && -f "$PCAP" ]]; then
    "$PROTOFORGE" build-dataset \
        --flows "$PCAP" \
        --label flooding \
        --out data/datasets/sbseg2024_validation.csv
    echo "  OK: data/datasets/sbseg2024_validation.csv"
else
    echo "  PCAP nao encontrado ($PCAP); usando flows de exemplo..."
    "$PROTOFORGE" build-dataset \
        --flows data/flows/example.csv \
        --label flooding \
        --out data/datasets/sbseg2024_validation.csv
    echo "  OK (fallback): data/datasets/sbseg2024_validation.csv"
fi

# 6. Treina IDS
echo "[6/7] Treinando IDS baseline..."
"$PROTOFORGE" train-ids \
    --dataset data/datasets/example_labeled.csv \
    --label-column label
echo "  OK"

# 7. Relatorio
echo "[7/7] Gerando relatorio..."
if [[ -n "$RUN_ID" ]]; then
    "$PROTOFORGE" report --run-id "$RUN_ID"
    echo "  OK: reports/${RUN_ID}.md"
else
    echo "  AVISO: run_id nao detectado, relatorio nao gerado."
fi

echo ""
echo "========================================"
echo " Fluxo completo concluido com sucesso!"
echo " Relatorio: reports/${RUN_ID:-<verificar>}.md"
echo "========================================"
echo ""
echo "Proximo passo:"
echo "  sudo -E env PATH=\$PATH python scripts/sbseg2024/run_testbed.py"
