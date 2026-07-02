#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
mkdir -p results

{
  echo "VulnForge AI — complete test suite"
  echo "UTC start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  "$PYTHON_BIN" --version
  "$PYTHON_BIN" -m pytest -q
  echo "UTC end: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee results/test-report.txt

