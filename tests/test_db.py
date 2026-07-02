"""Tests for SQLite repository."""

from vulnforge.db import get_connection
from vulnforge.models import RunRecord, ThreatAnalysis, Vulnerability
from vulnforge.vulnerability.repository import (
    get_analysis,
    get_run,
    get_vuln,
    list_vulns,
    save_analysis,
    save_run,
    upsert_vuln,
)


def test_upsert_and_get_vuln(tmp_path):
    conn = get_connection(str(tmp_path / "test.db"))
    vuln = Vulnerability(id="CVE-2024-TEST", title="T", cvss=5.0)
    upsert_vuln(conn, vuln)
    fetched = get_vuln(conn, "CVE-2024-TEST")
    assert fetched is not None
    assert fetched.title == "T"
    assert fetched.cvss == 5.0
    conn.close()


def test_list_vulns(tmp_path):
    conn = get_connection(str(tmp_path / "test.db"))
    upsert_vuln(conn, Vulnerability(id="A", title="A"))
    upsert_vuln(conn, Vulnerability(id="B", title="B"))
    assert len(list_vulns(conn)) == 2
    conn.close()


def test_save_and_get_analysis(tmp_path):
    conn = get_connection(str(tmp_path / "test.db"))
    analysis = ThreatAnalysis(protocol="XRCE-DDS", likely_attack_type="flooding")
    save_analysis(conn, "CVE-A", analysis)
    fetched = get_analysis(conn, "CVE-A")
    assert fetched is not None
    assert fetched.protocol == "XRCE-DDS"
    conn.close()


def test_save_and_get_run(tmp_path):
    conn = get_connection(str(tmp_path / "test.db"))
    record = RunRecord(run_id="r1", scenario_id="s1", started_at="now")
    save_run(conn, record, "yaml")
    fetched = get_run(conn, "r1")
    assert fetched is not None
    assert fetched.scenario_id == "s1"
    conn.close()
