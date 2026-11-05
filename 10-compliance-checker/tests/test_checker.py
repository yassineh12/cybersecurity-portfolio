import json
import tempfile
from pathlib import Path

from checker import (
    VERSION,
    OWASP_CONTROLS,
    CIS_CONTROLS,
    NIST_CSF_CONTROLS,
    Control,
    _build_report,
    from_reports,
    to_markdown,
    grade,
)


def test_owasp_has_10_controls():
    assert len(OWASP_CONTROLS) == 10


def test_cis_has_5_controls():
    assert len(CIS_CONTROLS) == 5


def test_all_controls_have_required_fields():
    for c in OWASP_CONTROLS + CIS_CONTROLS:
        assert c.framework in ("OWASP", "CIS")
        assert c.control_id
        assert c.name
        assert c.description
        assert c.severity in ("critical", "high", "medium", "low", "info")
        assert c.remediation


def test_build_report_all_pass():
    controls = [
        Control(framework="OWASP", control_id="A01", name="Test",
                description="Test", status="pass", severity="high"),
        Control(framework="OWASP", control_id="A02", name="Test2",
                description="Test2", status="pass", severity="critical"),
    ]
    report = _build_report("https://example.com", controls)
    assert report.summary["compliance_percentage"] == 100
    assert report.summary["status_counts"]["pass"] == 2
    assert report.summary["status_counts"]["fail"] == 0


def test_build_report_mixed():
    controls = [
        Control(framework="OWASP", control_id="A01", name="Pass",
                description="T", status="pass", severity="high"),
        Control(framework="OWASP", control_id="A02", name="Fail",
                description="T", status="fail", severity="critical"),
        Control(framework="CIS", control_id="CIS-1", name="Warn",
                description="T", status="warning", severity="medium"),
    ]
    report = _build_report("https://example.com", controls)
    assert report.summary["compliance_percentage"] == 33
    assert report.summary["status_counts"]["pass"] == 1
    assert report.summary["status_counts"]["fail"] == 1
    assert report.summary["status_counts"]["warning"] == 1


def test_build_report_no_testable():
    controls = [
        Control(framework="OWASP", control_id="A01", name="NT",
                description="T", status="not-tested", severity="high"),
    ]
    report = _build_report("https://example.com", controls)
    assert report.summary["compliance_percentage"] == 0


def test_from_reports_with_header_findings():
    data = {
        "target": "https://example.com",
        "findings": [
            {"category": "missing-header", "description": "Missing CSP"},
            {"category": "missing-header", "description": "Missing HSTS"},
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        report = from_reports([f.name])

    a05 = [c for c in report.controls if c.control_id == "A05"]
    assert a05[0].status == "fail"

    cis_hdr = [c for c in report.controls if c.control_id == "CIS-HDR"]
    assert cis_hdr[0].status == "fail"
    Path(f.name).unlink()


def test_from_reports_with_injection_findings():
    data = {
        "findings": [
            {"category": "sqli", "description": "SQL injection in /products"},
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        report = from_reports([f.name])

    a03 = [c for c in report.controls if c.control_id == "A03"]
    assert a03[0].status == "fail"
    Path(f.name).unlink()


def test_from_reports_with_vuln_findings():
    data = {
        "findings": [
            {"category": "cve", "description": "CVE-2021-12345 in nginx"},
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        report = from_reports([f.name])

    a06 = [c for c in report.controls if c.control_id == "A06"]
    assert a06[0].status == "fail"
    Path(f.name).unlink()


def test_from_reports_clean():
    data = {"target": "https://clean.example.com", "findings": []}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        report = from_reports([f.name])

    assert all(c.status in ("not-tested",) for c in report.controls)
    Path(f.name).unlink()


def test_from_reports_missing_file():
    report = from_reports(["/nonexistent/file.json"])
    assert report.target == "multiple-sources"


def test_to_markdown_structure():
    controls = [
        Control(framework="OWASP", control_id="A01", name="BAC",
                description="T", status="fail", severity="critical",
                findings=["Missing auth check"], remediation="Add auth"),
        Control(framework="CIS", control_id="CIS-TLS", name="TLS",
                description="T", status="pass", severity="critical",
                findings=["TLS ok"]),
    ]
    report = _build_report("https://example.com", controls)
    md = to_markdown(report)
    assert "# Security compliance report" in md
    assert "OWASP controls" in md
    assert "CIS controls" in md
    assert "Remediation plan" in md
    assert "A01" in md


def test_to_markdown_no_failures():
    controls = [
        Control(framework="OWASP", control_id="A01", name="BAC",
                description="T", status="pass", severity="critical"),
    ]
    report = _build_report("https://example.com", controls)
    md = to_markdown(report)
    assert "Remediation plan" not in md


def test_framework_scores_in_summary():
    controls = [
        Control(framework="OWASP", control_id="A01", name="T",
                description="T", status="pass", severity="high"),
        Control(framework="CIS", control_id="CIS-1", name="T",
                description="T", status="fail", severity="high"),
    ]
    report = _build_report("https://example.com", controls)
    fw_scores = report.summary["framework_scores"]
    assert fw_scores["OWASP"]["pass"] == 1
    assert fw_scores["CIS"]["fail"] == 1


def test_version_string():
    assert VERSION
    parts = VERSION.split(".")
    assert len(parts) == 3


def test_nist_csf_controls_exist():
    assert len(NIST_CSF_CONTROLS) >= 5
    for c in NIST_CSF_CONTROLS:
        assert c.framework == "NIST-CSF"
        assert c.control_id
        assert c.name
        assert c.remediation


def test_grade_boundaries():
    assert grade(100) == "A"
    assert grade(90) == "A"
    assert grade(89) == "B"
    assert grade(80) == "B"
    assert grade(79) == "C"
    assert grade(70) == "C"
    assert grade(69) == "D"
    assert grade(60) == "D"
    assert grade(59) == "F"
    assert grade(0) == "F"


def test_grade_in_report():
    controls = [
        Control(framework="OWASP", control_id="A01", name="Test",
                description="T", status="pass", severity="high"),
    ]
    report = _build_report("https://example.com", controls)
    assert "grade" in report.summary
    assert report.summary["grade"] == "A"


def test_grade_in_markdown():
    controls = [
        Control(framework="OWASP", control_id="A01", name="Test",
                description="T", status="pass", severity="high"),
    ]
    report = _build_report("https://example.com", controls)
    md = to_markdown(report)
    assert "Grade:" in md


def test_build_report_with_nist():
    controls = [
        Control(framework="OWASP", control_id="A01", name="BAC",
                description="T", status="pass", severity="critical"),
        Control(framework="NIST-CSF", control_id="PR.DS", name="Data Security",
                description="T", status="fail", severity="critical",
                findings=["No encryption"]),
    ]
    report = _build_report("https://example.com", controls)
    assert "NIST-CSF" in report.frameworks
    fw_scores = report.summary["framework_scores"]
    assert "NIST-CSF" in fw_scores


def test_from_reports_with_framework_filter():
    data = {
        "target": "https://example.com",
        "findings": [
            {"category": "missing-header", "description": "Missing CSP"},
        ],
    }
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        report = from_reports([f.name], frameworks=["CIS"])

    frameworks = {c.framework for c in report.controls}
    assert "CIS" in frameworks
    assert "OWASP" not in frameworks
    assert "NIST-CSF" not in frameworks
    Path(f.name).unlink()
