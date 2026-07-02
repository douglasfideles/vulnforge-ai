"""Tests for vulnerability normalizer."""

import pytest

from vulnforge.vulnerability.normalizer import import_vulns


def test_normalize_json(tmp_path):
    path = tmp_path / "vulns.json"
    path.write_text(
        '[{"cve": "CVE-2024-0001", "title": "Test", "cvss": 7.5, "summary": "desc"}]'
    )
    vulns = import_vulns(path)
    assert len(vulns) == 1
    assert vulns[0].id == "CVE-2024-0001"
    assert vulns[0].cvss == 7.5
    assert vulns[0].severity == "high"


def test_normalize_csv(tmp_path):
    path = tmp_path / "vulns.csv"
    path.write_text("cve_id,name,cvss_score\nCVE-2024-0002,Test,4.5\n")
    vulns = import_vulns(path)
    assert len(vulns) == 1
    assert vulns[0].id == "CVE-2024-0002"
    assert vulns[0].severity == "medium"


def test_cvss_clamp():
    from vulnforge.vulnerability.normalizer import _coerce_record
    v = _coerce_record({"id": "X", "cvss": 15.0}, 1)
    assert v is not None
    assert v.cvss == 10.0


def test_unknown_id():
    from vulnforge.vulnerability.normalizer import _coerce_record
    v = _coerce_record({"title": "No id"}, 1)
    assert v is not None
    assert v.id == "UNKNOWN-1"


def test_derive_severity():
    from vulnforge.vulnerability.normalizer import _derive_severity
    assert _derive_severity(9.5) == "critical"
    assert _derive_severity(7.0) == "high"
    assert _derive_severity(4.0) == "medium"
    assert _derive_severity(0.5) == "low"
    assert _derive_severity(0.0) == "none"
    assert _derive_severity(None) == "unknown"
