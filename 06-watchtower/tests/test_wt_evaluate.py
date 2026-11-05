import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import importlib.util
from datetime import datetime, timezone

import pytest

from watchtower.models import Alert, Incident, ScanResult

# tools/ is not a package; load evaluate.py under a unique module name so it
# cannot collide with any other "tools" or "evaluate" module in the repo.
_SPEC = importlib.util.spec_from_file_location(
    "wt_tools_evaluate", Path(__file__).resolve().parents[1] / "tools" / "evaluate.py")
ev = importlib.util.module_from_spec(_SPEC)
sys.modules["wt_tools_evaluate"] = ev
_SPEC.loader.exec_module(ev)

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def make_alert(ip, rule_id="SIG-SQLI", severity="high"):
    return Alert(rule_id=rule_id, title=rule_id, severity=severity, client_ip=ip,
                 first_seen=T0, last_seen=T0, event_count=1, technique="T1190")


def make_incident(ip, rules=("SIG-SQLI",), severity="high"):
    alerts = [make_alert(ip, r, severity) for r in rules]
    return Incident(client_ip=ip, alerts=alerts, score=50, severity=severity,
                    stages=["exploit"], first_seen=T0, last_seen=T0)


def fake_engine(incidents, calls=None):
    """Return a run_fn that ignores the log and returns these incidents."""
    def run(paths, config=None, fmt="auto"):
        if calls is not None:
            calls.append({"paths": paths, "config": config, "fmt": fmt})
        alerts = [a for inc in incidents for a in inc.alerts]
        return ScanResult(incidents=list(incidents), alerts=alerts, stats={}, generated_at=T0)
    return run


@pytest.fixture
def write_csv(tmp_path):
    def _write(text, name="labels.csv"):
        p = tmp_path / name
        p.write_text(text, encoding="utf-8")
        return p
    return _write


@pytest.fixture
def log_file(tmp_path):
    p = tmp_path / "access.log"
    p.write_text("", encoding="utf-8")
    return p


STANDARD_LABELS = (
    "client_ip,label,scenario\n"
    "203.0.113.10,malicious,sqli\n"
    "203.0.113.11,malicious,scanner\n"
    "203.0.113.12,malicious,brute_force\n"
    "192.0.2.1,benign,browsing\n"
    "192.0.2.2,benign,browsing\n"
    "192.0.2.3,benign,noisy_404\n"
)


# --------------------------------------------------------------------------
# metric maths
# --------------------------------------------------------------------------

class TestMetrics:
    def test_safe_div_zero_denominator(self):
        assert ev.safe_div(5, 0) == 0.0
        assert ev.safe_div(0, 0) == 0.0

    def test_safe_div_normal(self):
        assert ev.safe_div(1, 4) == 0.25

    def test_perfect(self):
        assert ev.compute_metrics(5, 0, 0) == (1.0, 1.0, 1.0)

    def test_known_values(self):
        p, r, f1 = ev.compute_metrics(tp=6, fp=2, fn=4)
        assert p == pytest.approx(0.75)
        assert r == pytest.approx(0.6)
        assert f1 == pytest.approx(2 * 0.75 * 0.6 / 1.35)

    def test_no_flags_at_all(self):
        # flagged nobody: precision 0/0 and recall 0/n, must not raise
        assert ev.compute_metrics(0, 0, 3) == (0.0, 0.0, 0.0)

    def test_everything_zero(self):
        assert ev.compute_metrics(0, 0, 0) == (0.0, 0.0, 0.0)

    def test_only_false_positives(self):
        assert ev.compute_metrics(0, 4, 0) == (0.0, 0.0, 0.0)

    def test_f1_is_harmonic_mean(self):
        p, r, f1 = ev.compute_metrics(tp=1, fp=0, fn=9)
        assert p == 1.0 and r == pytest.approx(0.1)
        assert f1 == pytest.approx(2 * 1.0 * 0.1 / 1.1)
        assert f1 < (p + r) / 2


# --------------------------------------------------------------------------
# label loading
# --------------------------------------------------------------------------

class TestLoadLabels:
    def test_basic(self, write_csv):
        labels, skipped = ev.load_labels(write_csv(STANDARD_LABELS))
        assert skipped == 0
        assert len(labels) == 6
        assert labels["203.0.113.10"].label == "malicious"
        assert labels["203.0.113.10"].scenario == "sqli"
        assert labels["192.0.2.3"].label == "benign"

    def test_whitespace_case_and_bom(self, write_csv):
        text = "﻿ Client_IP , Label , Scenario \n 203.0.113.5 , MALICIOUS , Log4Shell \n"
        labels, skipped = ev.load_labels(write_csv(text))
        assert skipped == 0
        assert labels["203.0.113.5"].label == "malicious"
        assert labels["203.0.113.5"].scenario == "Log4Shell"

    def test_blank_lines_ignored(self, write_csv):
        text = "client_ip,label,scenario\n\n192.0.2.1,benign,browsing\n,,\n"
        labels, skipped = ev.load_labels(write_csv(text))
        assert list(labels) == ["192.0.2.1"]
        assert skipped == 0

    def test_bad_rows_skipped_and_counted(self, write_csv):
        text = ("client_ip,label,scenario\n"
                "192.0.2.1,suspicious,odd\n"       # unknown label
                ",malicious,no_ip\n"               # no ip
                "192.0.2.2,benign,browsing\n")
        labels, skipped = ev.load_labels(write_csv(text))
        assert list(labels) == ["192.0.2.2"]
        assert skipped == 2

    def test_missing_scenario_column(self, write_csv):
        labels, _ = ev.load_labels(write_csv("client_ip,label\n192.0.2.1,benign\n"))
        assert labels["192.0.2.1"].scenario == "unspecified"

    def test_empty_scenario_value(self, write_csv):
        labels, _ = ev.load_labels(write_csv("client_ip,label,scenario\n192.0.2.1,benign,\n"))
        assert labels["192.0.2.1"].scenario == "unspecified"

    def test_conflicting_duplicate_malicious_wins(self, write_csv):
        text = ("client_ip,label,scenario\n"
                "203.0.113.9,malicious,sqli\n"
                "203.0.113.9,benign,browsing\n")
        labels, _ = ev.load_labels(write_csv(text))
        assert labels["203.0.113.9"].label == "malicious"
        assert labels["203.0.113.9"].scenario == "sqli"

    def test_conflicting_duplicate_order_independent(self, write_csv):
        text = ("client_ip,label,scenario\n"
                "203.0.113.9,benign,browsing\n"
                "203.0.113.9,malicious,sqli\n")
        labels, _ = ev.load_labels(write_csv(text))
        assert labels["203.0.113.9"].label == "malicious"

    def test_empty_file(self, write_csv):
        assert ev.load_labels(write_csv("")) == ({}, 0)

    def test_header_only(self, write_csv):
        assert ev.load_labels(write_csv("client_ip,label,scenario\n")) == ({}, 0)

    def test_wrong_columns_raises(self, write_csv):
        with pytest.raises(ValueError, match="client_ip"):
            ev.load_labels(write_csv("ip,verdict\n192.0.2.1,benign\n"))


# --------------------------------------------------------------------------
# flagged-client extraction and severity floor
# --------------------------------------------------------------------------

class TestFlaggedClients:
    def _result(self, incidents):
        return fake_engine(incidents)([])

    def test_rule_ids_sorted_unique(self):
        res = self._result([make_incident("203.0.113.1", ("SIG-XSS", "SIG-SQLI", "SIG-XSS"))])
        assert ev.flagged_clients(res) == {"203.0.113.1": ("SIG-SQLI", "SIG-XSS")}

    def test_multiple_incidents_same_ip_merge(self):
        res = self._result([make_incident("203.0.113.1", ("SIG-SQLI",)),
                            make_incident("203.0.113.1", ("BEH-404-BURST",), "medium")])
        assert ev.flagged_clients(res)["203.0.113.1"] == ("BEH-404-BURST", "SIG-SQLI")

    def test_min_severity_filters(self):
        res = self._result([make_incident("203.0.113.1", severity="low"),
                            make_incident("203.0.113.2", severity="medium"),
                            make_incident("203.0.113.3", severity="high"),
                            make_incident("203.0.113.4", severity="critical")])
        assert set(ev.flagged_clients(res)) == {"203.0.113.1", "203.0.113.2",
                                                "203.0.113.3", "203.0.113.4"}
        assert set(ev.flagged_clients(res, "high")) == {"203.0.113.3", "203.0.113.4"}
        assert set(ev.flagged_clients(res, "critical")) == {"203.0.113.4"}

    def test_no_incidents(self):
        assert ev.flagged_clients(self._result([])) == {}

    def test_alerts_without_incident_do_not_flag(self):
        res = ScanResult(incidents=[], alerts=[make_alert("203.0.113.1")], stats={}, generated_at=T0)
        assert ev.flagged_clients(res) == {}


# --------------------------------------------------------------------------
# end-to-end evaluate() with a fake engine
# --------------------------------------------------------------------------

class TestEvaluate:
    def test_confusion_matrix(self, write_csv, log_file):
        engine = fake_engine([
            make_incident("203.0.113.10", ("SIG-SQLI",)),               # TP
            make_incident("203.0.113.11", ("SIG-UA-SCANNER",), "medium"),  # TP
            make_incident("192.0.2.3", ("BEH-404-BURST",), "medium"),   # FP
        ])
        res = ev.evaluate(log_file, write_csv(STANDARD_LABELS), run_fn=engine)
        assert (res.tp, res.fp, res.fn, res.tn) == (2, 1, 1, 2)
        assert res.total == 6
        assert res.precision == pytest.approx(2 / 3)
        assert res.recall == pytest.approx(2 / 3)
        assert res.f1 == pytest.approx(2 / 3)
        assert res.false_positives == [("192.0.2.3", "noisy_404", ("BEH-404-BURST",))]
        assert res.missed == [("203.0.113.12", "brute_force")]

    def test_per_scenario(self, write_csv, log_file):
        engine = fake_engine([make_incident("203.0.113.10"), make_incident("192.0.2.3")])
        res = ev.evaluate(log_file, write_csv(STANDARD_LABELS), run_fn=engine)
        assert res.per_scenario["sqli"] == {"clients": 1, "detected": 1, "label": "malicious"}
        assert res.per_scenario["browsing"] == {"clients": 2, "detected": 0, "label": "benign"}
        assert res.per_scenario["noisy_404"] == {"clients": 1, "detected": 1, "label": "benign"}
        assert res.per_scenario["brute_force"]["detected"] == 0

    def test_mixed_scenario_label(self, write_csv, log_file):
        text = ("client_ip,label,scenario\n"
                "192.0.2.1,benign,shared\n"
                "203.0.113.1,malicious,shared\n")
        res = ev.evaluate(log_file, write_csv(text), run_fn=fake_engine([]))
        assert res.per_scenario["shared"]["label"] == "mixed"
        assert res.per_scenario["shared"]["clients"] == 2

    def test_perfect_detection(self, write_csv, log_file):
        engine = fake_engine([make_incident(ip) for ip in
                              ("203.0.113.10", "203.0.113.11", "203.0.113.12")])
        res = ev.evaluate(log_file, write_csv(STANDARD_LABELS), run_fn=engine)
        assert (res.precision, res.recall, res.f1) == (1.0, 1.0, 1.0)
        assert res.false_positives == [] and res.missed == []

    def test_engine_flags_nobody(self, write_csv, log_file):
        res = ev.evaluate(log_file, write_csv(STANDARD_LABELS), run_fn=fake_engine([]))
        assert (res.tp, res.fp, res.fn, res.tn) == (0, 0, 3, 3)
        assert (res.precision, res.recall, res.f1) == (0.0, 0.0, 0.0)

    def test_labelled_client_absent_from_log(self, write_csv, log_file):
        # the engine never saw 203.0.113.12 or 192.0.2.2: still scored
        engine = fake_engine([make_incident("203.0.113.10"), make_incident("203.0.113.11")])
        res = ev.evaluate(log_file, write_csv(STANDARD_LABELS), run_fn=engine)
        assert ("203.0.113.12", "brute_force") in res.missed
        assert res.tn == 3

    def test_unlabelled_flagged_excluded(self, write_csv, log_file):
        engine = fake_engine([make_incident("198.51.100.99", ("SIG-CMDI",)),
                              make_incident("203.0.113.10")])
        res = ev.evaluate(log_file, write_csv(STANDARD_LABELS), run_fn=engine)
        assert res.unlabelled_flagged == [("198.51.100.99", ("SIG-CMDI",))]
        assert res.fp == 0 and res.tp == 1
        assert res.total == 6

    def test_only_benign_labels(self, write_csv, log_file):
        text = "client_ip,label,scenario\n192.0.2.1,benign,browsing\n"
        res = ev.evaluate(log_file, write_csv(text), run_fn=fake_engine([make_incident("192.0.2.1")]))
        assert (res.tp, res.fp, res.fn, res.tn) == (0, 1, 0, 0)
        assert res.recall == 0.0 and res.precision == 0.0

    def test_empty_labels(self, write_csv, log_file):
        res = ev.evaluate(log_file, write_csv("client_ip,label,scenario\n"),
                          run_fn=fake_engine([make_incident("192.0.2.1")]))
        assert res.total == 0
        assert res.unlabelled_flagged == [("192.0.2.1", ("SIG-SQLI",))]

    def test_min_severity_tradeoff(self, write_csv, log_file):
        engine = fake_engine([
            make_incident("203.0.113.10", ("SIG-SQLI",), "high"),
            make_incident("203.0.113.11", ("SIG-UA-SCANNER",), "medium"),
            make_incident("203.0.113.12", ("BEH-BRUTE-SUCCESS",), "critical"),
            make_incident("192.0.2.3", ("BEH-404-BURST",), "medium"),
        ])
        labels = write_csv(STANDARD_LABELS)
        loose = ev.evaluate(log_file, labels, run_fn=engine)
        strict = ev.evaluate(log_file, labels, run_fn=engine, min_severity="high")
        assert loose.recall == 1.0 and loose.precision == 0.75
        assert strict.recall == pytest.approx(2 / 3) and strict.precision == 1.0
        assert strict.min_severity == "high"
        assert strict.missed == [("203.0.113.11", "scanner")]

    def test_bad_min_severity(self, write_csv, log_file):
        with pytest.raises(ValueError):
            ev.evaluate(log_file, write_csv(STANDARD_LABELS), run_fn=fake_engine([]),
                        min_severity="urgent")

    def test_run_fn_receives_args(self, write_csv, log_file):
        calls = []
        sentinel = object()
        ev.evaluate(log_file, write_csv(STANDARD_LABELS), config=sentinel,
                    run_fn=fake_engine([], calls), fmt="combined")
        assert calls == [{"paths": [str(log_file)], "config": sentinel, "fmt": "combined"}]

    def test_labels_skipped_reported(self, write_csv, log_file):
        text = STANDARD_LABELS + "192.0.2.50,unknown,odd\n"
        res = ev.evaluate(log_file, write_csv(text), run_fn=fake_engine([]))
        assert res.labels_skipped == 1


# --------------------------------------------------------------------------
# presentation and CLI
# --------------------------------------------------------------------------

class TestOutput:
    def _res(self, write_csv, log_file, incidents):
        return ev.evaluate(log_file, write_csv(STANDARD_LABELS), run_fn=fake_engine(incidents))

    def test_table_mentions_everything(self, write_csv, log_file):
        res = self._res(write_csv, log_file, [make_incident("203.0.113.10"),
                                              make_incident("192.0.2.3", ("BEH-404-BURST",))])
        table = ev.format_table(res)
        for needle in ("sqli", "noisy_404", "MISSED", "FALSE POS", "Precision", "Recall",
                       "F1", "BEH-404-BURST", "203.0.113.12", "TP 1"):
            assert needle in table

    def test_verdict_pass_and_fail(self, write_csv, log_file):
        res = self._res(write_csv, log_file, [make_incident("203.0.113.10")])
        assert ev.verdict(res, 0.0).startswith("VERDICT: PASS")
        assert ev.verdict(res, 0.5).startswith("VERDICT: FAIL")
        assert "1/3" in ev.verdict(res, 0.0)


class TestCli:
    def test_exit_zero_default_gate(self, write_csv, log_file, capsys):
        code = ev.main([str(log_file), str(write_csv(STANDARD_LABELS))], run_fn=fake_engine([]))
        assert code == 0
        out = capsys.readouterr().out
        assert "VERDICT: PASS" in out and "Recall" in out

    def test_exit_one_below_min_recall(self, write_csv, log_file, capsys):
        engine = fake_engine([make_incident("203.0.113.10")])
        code = ev.main([str(log_file), str(write_csv(STANDARD_LABELS)), "--min-recall", "0.9"],
                       run_fn=engine)
        assert code == 1
        assert "VERDICT: FAIL" in capsys.readouterr().out

    def test_exit_zero_at_exact_gate(self, write_csv, log_file):
        engine = fake_engine([make_incident(ip) for ip in
                              ("203.0.113.10", "203.0.113.11", "203.0.113.12")])
        code = ev.main([str(log_file), str(write_csv(STANDARD_LABELS)), "--min-recall", "1.0"],
                       run_fn=engine)
        assert code == 0

    def test_min_severity_flag(self, write_csv, log_file, capsys):
        engine = fake_engine([make_incident("203.0.113.10", severity="medium")])
        ev.main([str(log_file), str(write_csv(STANDARD_LABELS)), "--min-severity", "high"],
                run_fn=engine)
        out = capsys.readouterr().out
        assert "severity >= high" in out
        assert "TP 0" in out

    def test_missing_file_exit_two(self, write_csv, tmp_path, capsys):
        code = ev.main([str(tmp_path / "nope.log"), str(write_csv(STANDARD_LABELS))],
                       run_fn=fake_engine([]))
        assert code == 2
        assert "no such file" in capsys.readouterr().err

    def test_bad_labels_header_exit_two(self, write_csv, log_file, capsys):
        code = ev.main([str(log_file), str(write_csv("a,b\n1,2\n"))], run_fn=fake_engine([]))
        assert code == 2

    def test_min_recall_out_of_range(self, write_csv, log_file):
        code = ev.main([str(log_file), str(write_csv(STANDARD_LABELS)), "--min-recall", "1.5"],
                       run_fn=fake_engine([]))
        assert code == 2

    def test_invalid_severity_choice(self, write_csv, log_file):
        with pytest.raises(SystemExit) as exc:
            ev.main([str(log_file), str(write_csv(STANDARD_LABELS)), "--min-severity", "urgent"],
                    run_fn=fake_engine([]))
        assert exc.value.code == 2
