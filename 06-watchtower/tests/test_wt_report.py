import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from watchtower.models import Alert, Incident, ScanResult
from watchtower.report import (recommended_actions, technique_url, to_html,
                               to_json, to_markdown, write_reports)

T0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 1, 1, 10, 5, tzinfo=timezone.utc)
XSS = '1.2.3.4 "GET /?q=<script>alert(1)</script> </details>" 200'


def alert(rule="SIG-XSS", tech="T1190", evidence=None, detail="", sev="high"):
    return Alert(rule, "Title " + rule, sev, "203.0.113.9", T0, T1, 3, tech,
                 evidence if evidence is not None else [XSS], detail)


def result(alerts=None, stages=("recon", "exploit"), summary="Scanner then exploit"):
    alerts = alerts if alerts is not None else [alert()]
    inc = Incident("203.0.113.9", alerts, 80, "high", list(stages), T0, T1, summary)
    return ScanResult([inc], alerts, stats(1), T1)


def stats(n=0):
    return {"lines_read": 10, "lines_parsed": 9, "lines_malformed": 1,
            "unique_clients": 4, "time_start": "2026-01-01T10:00:00+00:00",
            "time_end": "2026-01-01T10:05:00+00:00", "files": ["a.log"],
            "incidents_by_severity": {"high": n} if n else {}}


def empty():
    return ScanResult([], [], stats(), T1)


def test_technique_url_subtechnique_uses_slash():
    assert technique_url("T1595.002") == "https://attack.mitre.org/techniques/T1595/002/"
    assert technique_url("T1190") == "https://attack.mitre.org/techniques/T1190/"
    assert technique_url('x"><script>') is None


def test_markdown_structure():
    md = to_markdown(result([alert("SIG-UA-SCANNER", "T1595.002")]))
    for part in ("# WATCHTOWER", "Scan summary", "Lines malformed: 1", "Unique clients: 4",
                 "Incidents by severity", "203.0.113.9", "score 80", "recon, exploit",
                 "[T1595.002](https://attack.mitre.org/techniques/T1595/002/)",
                 "Recommended actions", "WAF"):
        assert part in md


def test_markdown_pipe_in_text_does_not_break_table():
    a = alert(rule="SIG|X")
    a.title = "a|b"
    md = to_markdown(result([a]))
    row = next(l for l in md.splitlines() if l.startswith("| SIG"))
    assert "SIG\\|X" in row
    assert len(re.split(r"(?<!\\)\|", row)) == len(re.split(r"(?<!\\)\|", "| a | b | c | d | e | f |"))


def test_markdown_backtick_in_cell_neutralised():
    md = to_markdown(result([alert(rule="R`x")]))
    row = next(l for l in md.splitlines() if l.startswith("| R"))
    assert "`" not in row.replace("\\`", "")


def test_markdown_evidence_cannot_escape_fence():
    ev = ["bad ``` line", "worse ````` line", "# heading"]
    md = to_markdown(result([alert(evidence=ev)]))
    fence = "`" * 6
    assert fence + "text" in md
    lines = md.splitlines()
    start = lines.index(fence + "text")
    end = lines.index(fence, start + 1)
    assert lines[start + 1:end] == ev


def test_markdown_actions_by_stage():
    r = result([alert("BEH-BRUTE-SUCCESS", "T1110", sev="critical")], stages=("credential-access",))
    md = to_markdown(r)
    assert "reset the affected account" in md
    r2 = result([alert(detail="answered with 2xx")], stages=("exploit",))
    assert "2xx answer" in " ".join(recommended_actions(r2.incidents[0]))


def test_html_escapes_script_and_details():
    a = alert()
    a.title = "<img src=x onerror=1>"
    r = result([a], summary="<b>sum</b>")
    h = to_html(r)
    assert "<script>alert(1)</script>" not in h
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in h
    assert "&lt;/details&gt;" in h
    assert h.count("</details>") == 1
    assert "<img src=x" not in h and "<b>sum</b>" not in h


def test_html_escapes_ip_and_user_agent_fields():
    r = result()
    r.incidents[0].client_ip = '"><script>x</script>'
    h = to_html(r)
    assert "<script" not in h


def test_html_is_self_contained_and_themed():
    h = to_html(result())
    assert "<script" not in h.lower()
    assert "http://" not in h and "src=" not in h and "@import" not in h
    assert "prefers-color-scheme:dark" in h and ":root{" in h
    assert 'name="viewport"' in h
    assert "<details" in h and "sev-high" in h
    assert "https://attack.mitre.org/techniques/T1190/" in h


def test_empty_result_friendly_all_formats():
    r = empty()
    assert "No incidents" in to_markdown(r)
    assert "No incidents" in to_html(r)
    data = json.loads(to_json(r))
    assert data["incidents"] == [] and data["alerts"] == []


def test_json_round_trip():
    r = result()
    data = json.loads(to_json(r))
    assert data == r.to_dict()
    assert data["incidents"][0]["alerts"][0]["evidence"] == [XSS]


def test_write_reports_creates_dir_and_files(tmp_path):
    out = tmp_path / "nested" / "out"
    paths = write_reports(result(), out)
    assert set(paths) == {"md", "json", "html"}
    assert [p.name for p in (paths["md"], paths["json"], paths["html"])] == \
        ["report.md", "report.json", "report.html"]
    assert all(p.exists() and p.stat().st_size > 0 for p in paths.values())
    json.loads(paths["json"].read_text(encoding="utf-8"))


def test_odd_values_do_not_raise():
    a = alert(tech="", evidence=[], detail="")
    r = result([a], stages=())
    assert to_markdown(r) and to_html(r)


PAYLOAD = "[click-to-unblock](https://evil.example/phish)![t](https://evil.example/px.png)"


def test_markdown_link_and_image_injection_neutralised():
    a = alert(detail=PAYLOAD)
    a.title = PAYLOAD
    r = result([a], summary=PAYLOAD)
    r.incidents[0].client_ip = PAYLOAD
    md = to_markdown(r)
    # the only live links allowed are the generated ATT&CK ones
    assert not re.search(r"(?<!\\)\]\((?!https://attack\.mitre\.org)", md)
    assert not re.search(r"(?<!\\)!\[", md)
    assert "\\]\\(" in md


def test_markdown_headings_stay_single_line():
    r = result()
    r.incidents[0].client_ip = "1.2.3.4\n# Injected\r\n- item\x00"
    md = to_markdown(r)
    assert not any(l.startswith("# Injected") or l.startswith("- item") for l in md.splitlines())
    assert "\x00" not in md
    heads = [l for l in md.splitlines() if l.startswith("### ")]
    assert len(heads) == 1
