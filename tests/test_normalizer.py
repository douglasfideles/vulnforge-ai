"""Testes do normalizador de vulnerabilidades."""

from vulnforge.vulnerability.normalizer import normalize_vuln


def test_aliases_are_resolved():
    raw = {"cve": "CVE-2024-9999", "summary": "desc aqui", "base_score": "8.2", "product": "Zenoh"}
    v = normalize_vuln(raw)
    assert v.id == "CVE-2024-9999"
    assert v.description == "desc aqui"
    assert v.cvss == 8.2
    assert v.affected_product == "Zenoh"


def test_severity_derived_from_cvss_when_missing():
    assert normalize_vuln({"id": "A", "cvss": 9.5}).severity == "critical"
    assert normalize_vuln({"id": "B", "cvss": 7.1}).severity == "high"
    assert normalize_vuln({"id": "C", "cvss": 4.0}).severity == "medium"
    assert normalize_vuln({"id": "D", "cvss": 1.0}).severity == "low"


def test_invalid_cvss_becomes_none():
    v = normalize_vuln({"id": "X", "cvss": "nao-e-numero"})
    assert v.cvss is None
    assert v.severity == "unknown"


def test_cvss_is_clamped():
    assert normalize_vuln({"id": "Y", "cvss": 99}).cvss == 10.0
    assert normalize_vuln({"id": "Z", "cvss": -3}).cvss == 0.0


def test_missing_id_gets_placeholder():
    v = normalize_vuln({"title": "sem id"})
    assert v.id.startswith("UNKNOWN-")
    assert v.title == "sem id"


def test_explicit_severity_is_preserved():
    v = normalize_vuln({"id": "S", "cvss": 2.0, "severity": "Critical"})
    assert v.severity == "critical"
