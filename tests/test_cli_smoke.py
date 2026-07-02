"""Smoke tests for CLI commands via subprocess."""

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def run_cmd():
    def _run(args):
        return subprocess.run(
            [sys.executable, "-m", "vulnforge.cli"] + args,
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parents[1],
        )
    return _run


def test_cli_help(run_cmd):
    result = run_cmd(["--help"])
    assert result.returncode == 0
    assert "protoforge" in result.stdout.lower() or "vulnforge" in result.stdout.lower()


def test_protocols_command(run_cmd):
    result = run_cmd(["protocols"])
    assert result.returncode == 0
    assert "XRCE-DDS" in result.stdout or "xrce-dds" in result.stdout
