#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
export VULNFORGE_LLM_PROVIDER=offline

"$PYTHON_BIN" scripts/reproduce.py "$@"

