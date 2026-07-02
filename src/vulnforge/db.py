from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .config import get_settings
from .models import RunRecord, ThreatAnalysis, Vulnerability


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    target = Path(path or get_settings().db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY, title TEXT, description TEXT, source TEXT, cvss REAL,
      severity TEXT, cwe TEXT, published_at TEXT, affected_product TEXT
    );
    CREATE TABLE IF NOT EXISTS analyses (
      vuln_id TEXT PRIMARY KEY, protocol TEXT, likely_attack_type TEXT, preconditions TEXT,
      expected_network_behavior TEXT, dataset_label TEXT, confidence REAL, safety_notes TEXT,
      source TEXT, created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS runs (
      run_id TEXT PRIMARY KEY, scenario_id TEXT, vuln_id TEXT, started_at TEXT, status TEXT,
      log_path TEXT, pcap_path TEXT, scenario_yaml TEXT,
      effect_verdict TEXT DEFAULT 'not_validated', responsive_before TEXT,
      responsive_after TEXT, anomalies TEXT, llm_model TEXT, llm_seed TEXT
    );
    """)
    return conn


def upsert_vuln(vuln: Vulnerability, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    fields = list(Vulnerability.model_fields)
    conn.execute(
        f"INSERT OR REPLACE INTO vulnerabilities ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
        [getattr(vuln, key) for key in fields],
    )
    conn.commit()
    if own:
        conn.close()


def get_vuln(vuln_id: str, conn=None) -> Vulnerability | None:
    own = conn is None
    conn = conn or connect()
    row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone()
    if own:
        conn.close()
    return Vulnerability(**dict(row)) if row else None


def list_vulns(conn=None) -> list[Vulnerability]:
    own = conn is None
    conn = conn or connect()
    rows = conn.execute("SELECT * FROM vulnerabilities ORDER BY id").fetchall()
    if own:
        conn.close()
    return [Vulnerability(**dict(row)) for row in rows]


def save_analysis(vuln_id: str, analysis: ThreatAnalysis, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    data = analysis.model_dump(mode="json")
    fields = list(data)
    conn.execute(
        f"INSERT OR REPLACE INTO analyses (vuln_id,{','.join(fields)},created_at) "
        f"VALUES ({','.join('?' for _ in range(len(fields)+2))})",
        [vuln_id, *data.values(), datetime.now(timezone.utc).isoformat()],
    )
    conn.commit()
    if own:
        conn.close()


def get_analysis(vuln_id: str, conn=None) -> ThreatAnalysis | None:
    own = conn is None
    conn = conn or connect()
    row = conn.execute("SELECT * FROM analyses WHERE vuln_id=?", (vuln_id,)).fetchone()
    if own:
        conn.close()
    if not row:
        return None
    data = dict(row)
    data.pop("vuln_id", None)
    data.pop("created_at", None)
    return ThreatAnalysis(**data)


def save_run(record: RunRecord, scenario_yaml: str, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    data = record.model_dump()
    fields = list(data)
    conn.execute(
        f"INSERT OR REPLACE INTO runs ({','.join(fields)},scenario_yaml) "
        f"VALUES ({','.join('?' for _ in range(len(fields)+1))})",
        [*data.values(), scenario_yaml],
    )
    conn.commit()
    if own:
        conn.close()


def get_run(run_id: str, conn=None) -> dict | None:
    own = conn is None
    conn = conn or connect()
    row = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if own:
        conn.close()
    return dict(row) if row else None

