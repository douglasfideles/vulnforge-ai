"""Conexao SQLite e inicializacao de schema."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .config import get_settings
from .logging_setup import get_logger

log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              TEXT PRIMARY KEY,
    title           TEXT,
    description     TEXT,
    source          TEXT,
    cvss            REAL,
    severity        TEXT,
    cwe             TEXT,
    published_at    TEXT,
    affected_product TEXT
);

CREATE TABLE IF NOT EXISTS analyses (
    vuln_id                  TEXT,
    protocol                 TEXT,
    likely_attack_type       TEXT,
    preconditions            TEXT,
    expected_network_behavior TEXT,
    dataset_label            TEXT,
    confidence               REAL,
    safety_notes             TEXT,
    source                   TEXT,
    created_at               TEXT,
    PRIMARY KEY (vuln_id)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    scenario_id  TEXT,
    vuln_id      TEXT,
    started_at   TEXT,
    status       TEXT,
    log_path     TEXT,
    pcap_path    TEXT,
    scenario_yaml TEXT,
    effect_verdict     TEXT DEFAULT 'not_validated',
    responsive_before  TEXT DEFAULT '',
    responsive_after   TEXT DEFAULT '',
    anomalies          TEXT DEFAULT '',
    llm_model          TEXT DEFAULT '',
    llm_seed           TEXT DEFAULT ''
);
"""

# Colunas adicionadas apos a v1 (migracao leve para bancos existentes).
_RUNS_EXTRA_COLUMNS = [
    ("effect_verdict", "TEXT DEFAULT 'not_validated'"),
    ("responsive_before", "TEXT DEFAULT ''"),
    ("responsive_after", "TEXT DEFAULT ''"),
    ("anomalies", "TEXT DEFAULT ''"),
    ("llm_model", "TEXT DEFAULT ''"),
    ("llm_seed", "TEXT DEFAULT ''"),
]


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    """Abre conexao SQLite garantindo o diretorio e o schema."""
    path = db_path or get_settings().db_path
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Cria as tabelas se nao existirem e aplica migracoes leves."""
    conn.executescript(_SCHEMA)
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
    for col, decl in _RUNS_EXTRA_COLUMNS:
        if col not in existing:
            conn.execute(f"ALTER TABLE runs ADD COLUMN {col} {decl}")
    conn.commit()
