#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# VulnForge AI - setup do ambiente local (venv + dependencias fixadas).
#
# Uso:   bash scripts/setup.sh
# Depois: source .venv/bin/activate && bash scripts/run-minimal.sh
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

PY="${PYTHON:-python3}"
echo "==> Criando virtualenv em .venv (Python: $("$PY" --version 2>&1))"
"$PY" -m venv .venv

# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Atualizando pip e instalando dependencias fixadas"
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .            # registra o entrypoint `protoforge`

[ -f .env ] || { cp .env.example .env && echo "==> .env criado a partir de .env.example"; }

echo
echo "Ambiente pronto. Ative com:  source .venv/bin/activate"
echo "Rode o teste minimo com:     bash scripts/run-minimal.sh"
