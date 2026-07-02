import json

import pytest

from vulnforge.vulnerability.normalizer import import_file, normalize_record, severity_for


@pytest.mark.parametrize(
    ("score", "expected"),
    [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"), (0.0, "none"), (None, "unknown")],
)
def test_severity_thresholds(score, expected):
    assert severity_for(score) == expected


def test_aliases_cvss_clamp_and_derived_severity():
    vuln = normalize_record({"CVE ID": "CVE-1", "Summary": "x", "BASE SCORE": "25", "Vendor Product": "agent"})
    assert (vuln.id, vuln.description, vuln.cvss, vuln.severity, vuln.affected_product) == ("CVE-1", "x", 10.0, "critical", "agent")


def test_bad_cvss_and_unknown_id():
    vuln = normalize_record({"score": "garbage"}, 7)
    assert vuln.id == "UNKNOWN-7"
    assert vuln.cvss is None
    assert vuln.severity == "unknown"


def test_import_wrapped_json_skips_non_objects(tmp_path):
    path = tmp_path / "v.json"
    path.write_text(json.dumps({"items": [{"id": "one"}, "skip", {"id": "two"}]}))
    assert [v.id for v in import_file(path)] == ["one", "two"]


def test_unsupported_extension(tmp_path):
    path = tmp_path / "v.txt"
    path.write_text("x")
    with pytest.raises(ValueError, match="json"):
        import_file(path)

