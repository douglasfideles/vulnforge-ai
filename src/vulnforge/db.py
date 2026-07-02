"""SQLite persistence layer with idempotent schema initialization."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from sqlite3 import Row

from .config import get_settings


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    cvss REAL,
    severity TEXT NOT NULL DEFAULT 'unknown',
    cwe TEXT NOT NULL DEFAULT '',
    published_at TEXT NOT NULL DEFAULT '',
    affected_product TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS analyses (
    vuln_id TEXT PRIMARY KEY,
    protocol TEXT NOT NULL DEFAULT 'unknown',
    likely_attack_type TEXT NOT NULL DEFAULT 'unknown',
    preconditions TEXT NOT NULL DEFAULT '',
    expected_network_behavior TEXT NOT NULL DEFAULT '',
    dataset_label TEXT NOT NULL DEFAULT 'unknown',
    confidence REAL NOT NULL DEFAULT 0.0,
    safety_notes TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'rules',
    created_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    vuln_id TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'created',
    log_path TEXT NOT NULL DEFAULT '',
    pcap_path TEXT NOT NULL DEFAULT '',
    scenario_yaml TEXT NOT NULL DEFAULT '',
    effect_verdict TEXT NOT NULL DEFAULT 'not_validated',
    responsive_before TEXT NOT NULL DEFAULT '',
    responsive_after TEXT NOT NULL DEFAULT '',
    anomalies TEXT NOT NULL DEFAULT '',
    llm_model TEXT NOT NULL DEFAULT '',
    llm_seed TEXT NOT NULL DEFAULT ''
);
"""

MIGRATIONS = [
    # Phase-2 effect-validation columns (idempotent).
    "ALTER TABLE runs ADD COLUMN effect_verdict TEXT NOT NULL DEFAULT 'not_validated';",
    "ALTER TABLE runs ADD COLUMN responsive_before TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE runs ADD COLUMN responsive_after TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE runs ADD COLUMN anomalies TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE runs ADD COLUMN llm_model TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE runs ADD COLUMN llm_seed TEXT NOT NULL DEFAULT '';",
]


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Open a SQLite connection, ensuring schema and migrations are applied."""
    if db_path is None:
        db_path = get_settings().db_path
    path = Path(db_path)
    _ensure_parent(path)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = Row
    conn.executescript(SCHEMA_SQL)
    for migration in MIGRATIONS:
        try:
            conn.execute(migration)
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    return conn
