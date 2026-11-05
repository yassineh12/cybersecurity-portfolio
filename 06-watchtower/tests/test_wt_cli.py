import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import io
import json
import subprocess
import types
from datetime import datetime, timedelta, timezone

import pytest

from watchtower import cli
from watchtower.cli import exit_code, format_summary, main
from watchtower.correlate import correlate
from watchtower.models import Alert, ScanResult

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def alert(rule, severity, ip, minute=0, detail=""):
    t = T0 + timedelta(minutes=minute)
    return Alert(rule, rule, severity, ip, t, t, 3, "T1190", [], detail)


def fake_result(alerts):
    incidents = correlate(alerts)
    sev = {s: sum(i.severity == s for i in incidents) for s in ("low", "medium", "high", "critical")}
    stats = {"lines_read": 10, "lines_parsed": 9, "lines_malformed": 1, "events_allowlisted": 2,
             "unique_clients": 4, "time_start": T0.isoformat(), "time_end": T0.isoformat(),
             "files": ["access.log"], "alerts_by_rule": {}, "incidents_by_severity": sev}
    return ScanResult(incidents, alerts, stats, T0)


@pytest.fixture
def patched(monkeypatch, tmp_path):
    """Replace the engine run and the report writer; record what they were given."""
    seen = {}
    alerts = [alert("SIG-SQLI", "high", "203.0.113.5"), alert("BEH-RATE-SPIKE", "low", "192.0.2.9")]

    def fake_run(paths, config=None, fmt="auto"):
        seen.update(paths=paths, config=config, fmt=fmt)
        return fake_result(alerts)

    def fake_write(result, out_dir):
        seen["written"] = result
        out_dir.mkdir(parents=True, exist_ok=True)
        return {k: out_dir / f"report.{k}" for k in ("md", "json", "html")}

    monkeypatch.setattr(cli, "run", fake_run)
    monkeypatch.setitem(sys.modules, "watchtower.report", types.SimpleNamespace(write_reports=fake_write))
    log = tmp_path / "access.log"
    log.write_text("x\n")
    seen["log"] = log
    return seen


def call(*argv):
    buf = io.StringIO()
    code = main(list(argv), stdout=buf)
    return code, buf.getvalue()


def test_exit_2_when_incident_at_default_fail_on(patched, tmp_path):
    code, out = call("scan", str(patched["log"]), "--out", str(tmp_path / "r"))
    assert code == 2
    assert "203.0.113.5" in out and "WATCHTOWER" in out
    assert patched["fmt"] == "auto"
    assert patched["config"].source.endswith("default.yaml")


def test_fail_on_levels(patched, tmp_path):
    log, out = str(patched["log"]), str(tmp_path)
    assert call("scan", log, "--out", out, "--fail-on", "critical")[0] == 0
    assert call("scan", log, "--out", out, "--fail-on", "low")[0] == 2
    assert call("scan", log, "--out", out, "--fail-on", "never")[0] == 0


def test_min_severity_filters_report_but_not_exit_code(patched, tmp_path):
    code, out = call("scan", str(patched["log"]), "--out", str(tmp_path),
                     "--min-severity", "critical", "--fail-on", "high")
    assert code == 2                                   # gating judged on the full scan
    assert patched["written"].incidents == []
    assert "No incidents" in out


def test_format_and_config_passed_through(patched, tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("allowlist: [192.0.2.10]\n")
    call("scan", str(patched["log"]), "--out", str(tmp_path), "--format", "jsonl", "--config", str(cfg))
    assert patched["fmt"] == "jsonl"
    assert patched["config"].is_allowlisted("192.0.2.10")


def test_bad_config_exits_1(patched, tmp_path, capsys):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("rules:\n  SIG-SQL: false\n")
    code, _ = call("scan", str(patched["log"]), "--config", str(cfg))
    assert code == 1
    assert "SIG-SQLI" in capsys.readouterr().err


def test_missing_log_exits_1(tmp_path, capsys):
    code, _ = call("scan", str(tmp_path / "nope.log"), "--out", str(tmp_path))
    assert code == 1
    assert "nope.log" in capsys.readouterr().err


def test_bad_arguments_exit_1_not_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "x.log", "--min-severity", "extreme"])
    assert exc.value.code == 1
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 1


def test_exit_code_function():
    r = fake_result([alert("SIG-XSS", "medium", "192.0.2.1")])
    assert exit_code(r, "high") == 0
    assert exit_code(r, "medium") == 2
    assert exit_code(fake_result([]), "low") == 0


def test_summary_strips_terminal_escapes_and_limits_rows():
    evil = alert("X-RULE", "low", "192.0.2.1")
    evil.title = "\x1b[2J\x1b[31mgotcha"
    alerts = [evil] + [alert("SIG-XSS", "medium", f"198.51.100.{n}") for n in range(12)]
    text = format_summary(fake_result(alerts), top=10)
    assert "\x1b" not in text
    assert "... and 3 more" in text
    assert "SCORE" in text and "incidents 13" in text


def test_python_dash_m_end_to_end(tmp_path):
    """Real parser, detectors and report writer through `python -m watchtower`."""
    for mod in ("watchtower.parsers", "watchtower.report", "watchtower.detectors.signatures",
                "watchtower.detectors.behaviour"):
        pytest.importorskip(mod)
    ip = "203.0.113.5"
    lines = []
    for s in range(3):
        ts = (T0 + timedelta(seconds=s)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{ip} - - [{ts}] "GET /.env HTTP/1.1" 404 0 "-" "sqlmap/1.7.2#stable"')
    ts = (T0 + timedelta(seconds=9)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    lines.append(f'{ip} - - [{ts}] "GET /item?id=1%27%20UNION%20SELECT%20NULL-- HTTP/1.1" 200 99 "-" "sqlmap/1.7.2#stable"')
    lines.append("not a log line")
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n")
    out = tmp_path / "reports"
    proc = subprocess.run([sys.executable, "-m", "watchtower", "scan", str(log), "--out", str(out)],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2, proc.stderr
    assert ip in proc.stdout
    for name in ("report.md", "report.json", "report.html"):
        assert (out / name).is_file()
    data = json.loads((out / "report.json").read_text())
    assert data["stats"]["lines_malformed"] == 1
    assert data["incidents"][0]["client_ip"] == ip


# --- untrustworthy input must not pass CI ---

def _real_modules():
    for mod in ("watchtower.parsers", "watchtower.report", "watchtower.detectors.signatures",
                "watchtower.detectors.behaviour"):
        pytest.importorskip(mod)


def test_wrong_format_exits_1_not_0(tmp_path, capsys):
    _real_modules()
    log = tmp_path / "access.jsonl"
    log.write_text("\n".join('{"time": "2026-03-01T12:00:%02dZ", "remote_addr": "192.0.2.1", '
                             '"request": "GET / HTTP/1.1", "status": 200}' % s for s in range(5)) + "\n")
    code, _ = call("scan", str(log), "--format", "combined", "--out", str(tmp_path / "r"))
    err = capsys.readouterr().err
    assert code == 1
    assert "no parseable log lines" in err and "--format combined" in err
    assert not (tmp_path / "r" / "report.json").exists()      # no misleading empty report


def test_empty_file_exits_1(tmp_path, capsys):
    _real_modules()
    log = tmp_path / "empty.log"
    log.write_text("")
    code, _ = call("scan", str(log), "--out", str(tmp_path))
    assert code == 1
    assert "input is empty" in capsys.readouterr().err


def test_max_malformed_threshold(patched, tmp_path, monkeypatch, capsys):
    def mostly_garbage(paths, config=None, fmt="auto"):
        r = fake_result([])
        r.stats.update(lines_read=10, lines_parsed=3, lines_malformed=7)
        return r

    monkeypatch.setattr(cli, "run", mostly_garbage)
    log, out = str(patched["log"]), str(tmp_path)
    assert call("scan", log, "--out", out)[0] == 1
    err = capsys.readouterr().err
    assert "7 of 10 lines malformed" in err and "--max-malformed" in err
    assert call("scan", log, "--out", out, "--max-malformed", "0.8")[0] == 0
    assert "warning: 7 of 10 lines malformed" in capsys.readouterr().err   # still warned
    with pytest.raises(SystemExit) as exc:
        main(["scan", log, "--max-malformed", "1.5"])
    assert exc.value.code == 1


def test_malformed_lines_warned_even_under_limit(patched, tmp_path, capsys):
    code, _ = call("scan", str(patched["log"]), "--out", str(tmp_path), "--fail-on", "never")
    assert code == 0
    assert "warning: 1 of 10 lines malformed" in capsys.readouterr().err


def test_read_error_warns_and_exits_1_even_with_incidents(patched, tmp_path, monkeypatch, capsys):
    def partial(paths, config=None, fmt="auto"):
        r = fake_result([alert("SIG-SQLI", "high", "203.0.113.5")])
        r.stats["read_errors"] = ["access.log.gz: EOFError: truncated"]
        return r

    monkeypatch.setattr(cli, "run", partial)
    code, out = call("scan", str(patched["log"]), "--out", str(tmp_path))
    err = capsys.readouterr().err
    assert code == 1
    assert "results are partial" in err and "access.log.gz: EOFError" in err
    assert "203.0.113.5" in out and "written" in patched          # partial report still written


def test_reader_exception_is_one_line_not_traceback(patched, tmp_path, monkeypatch, capsys):
    import gzip

    def boom(paths, config=None, fmt="auto"):
        raise gzip.BadGzipFile("Not a gzipped file (b'ab')")

    monkeypatch.setattr(cli, "run", boom)
    code, _ = call("scan", str(patched["log"]), "--out", str(tmp_path))
    err = capsys.readouterr().err
    assert code == 1
    assert err.strip() == "watchtower: cannot read logs: BadGzipFile: Not a gzipped file (b'ab')"


def test_corrupt_gzip_end_to_end_no_traceback(tmp_path):
    import gzip
    _real_modules()
    ts = T0.strftime("%d/%b/%Y:%H:%M:%S +0000")
    body = "".join(f'192.0.2.1 - - [{ts}] "GET /p{n} HTTP/1.1" 200 5 "-" "Mozilla/5.0"\n' for n in range(3000))
    data = gzip.compress(body.encode())
    log = tmp_path / "cut.log.gz"
    log.write_bytes(data[: len(data) // 2])
    proc = subprocess.run([sys.executable, "-m", "watchtower", "scan", str(log), "--out", str(tmp_path)],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert "results are partial" in proc.stderr and str(log) in proc.stderr
    assert proc.stderr.count("cut.log.gz:") == 2            # one warning + one error line, no duplicates
