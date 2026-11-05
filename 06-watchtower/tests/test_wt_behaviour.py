import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datetime import datetime, timedelta, timezone

from watchtower.detectors.behaviour import (
    BruteForceDetector, EnumerationDetector, RateDetector, is_login_path)
from watchtower.models import LogEvent

T0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def ev(sec, ip="192.0.2.1", method="GET", path="/x", status=404, n=0):
    return LogEvent(timestamp=T0 + timedelta(seconds=sec), client_ip=ip, method=method,
                    path=path, query="", status=status, bytes_sent=0, referrer="",
                    user_agent="", raw=f"line {ip} {sec} {n}")


def run(det, events):
    out = []
    for e in events:
        out += det.feed(e)
    return out + det.flush()


def test_enum_below_threshold():
    assert run(EnumerationDetector(5, 60), [ev(i) for i in range(4)]) == []


def test_enum_at_threshold():
    alerts = run(EnumerationDetector(5, 60), [ev(i) for i in range(5)])
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.rule_id, a.severity, a.technique) == ("BEH-404-BURST", "medium", "T1595.003")
    assert a.event_count == 5 and a.first_seen == T0


def test_enum_ignores_non_404():
    assert run(EnumerationDetector(3, 60), [ev(i, status=200) for i in range(10)]) == []


def test_enum_window_expiry():
    # 4 hits, long pause, 4 more: never 5 inside one 60s window
    evs = [ev(i) for i in range(4)] + [ev(200 + i) for i in range(4)]
    assert run(EnumerationDetector(5, 60), evs) == []


def test_enum_boundary_exactly_window_kept():
    # first event exactly window_seconds old is still inside the window
    evs = [ev(0)] + [ev(60 - 3 + i) for i in range(3)] + [ev(60)]
    assert len(run(EnumerationDetector(5, 60), evs)) == 1


def test_enum_extends_alert():
    alerts = run(EnumerationDetector(5, 60), [ev(i) for i in range(12)])
    assert len(alerts) == 1
    assert alerts[0].event_count == 12
    assert alerts[0].last_seen == T0 + timedelta(seconds=11)


def test_clients_isolated():
    evs = []
    for i in range(4):
        evs += [ev(i, ip="192.0.2.1"), ev(i, ip="192.0.2.2")]
    assert run(EnumerationDetector(5, 60), evs) == []
    evs.append(ev(5, ip="192.0.2.1"))
    alerts = run(EnumerationDetector(5, 60), evs)
    assert [a.client_ip for a in alerts] == ["192.0.2.1"]


def test_evidence_cap():
    alerts = run(EnumerationDetector(5, 60), [ev(i, n=i) for i in range(30)])
    assert len(alerts[0].evidence) == 5


def test_state_cleanup_after_window():
    det = EnumerationDetector(5, 60)
    for i in range(3000):
        det.feed(ev(0, ip=f"10.{i // 250}.{i % 250}.1"))
    assert len(det._windows) == 3000
    for i in range(1100):  # time moves on; sweeps drop the idle one-off clients
        det.feed(ev(1000 + i, ip="192.0.2.99"))
    assert len(det._windows) <= 2


def test_brute_below_and_at_threshold():
    mk = lambda n: [ev(i, method="POST", path="/login", status=401) for i in range(n)]
    assert run(BruteForceDetector(5, 300), mk(4)) == []
    alerts = run(BruteForceDetector(5, 300), mk(5))
    assert len(alerts) == 1
    assert (alerts[0].rule_id, alerts[0].severity, alerts[0].technique) == \
        ("BEH-BRUTE-FORCE", "high", "T1110")


def test_brute_403_counts_and_get_does_not():
    evs = [ev(i, method="POST", path="/login", status=403) for i in range(3)]
    evs += [ev(5 + i, method="GET", path="/login", status=401) for i in range(10)]
    assert len(run(BruteForceDetector(3, 300), evs)) == 1
    assert run(BruteForceDetector(4, 300), evs) == []


def test_brute_window_expiry():
    evs = [ev(i, method="POST", path="/login", status=401) for i in range(3)]
    evs += [ev(1000 + i, method="POST", path="/login", status=401) for i in range(3)]
    assert run(BruteForceDetector(5, 300), evs) == []


def test_brute_success_after_failures():
    evs = [ev(i, method="POST", path="/login", status=401) for i in range(5)]
    evs.append(ev(10, method="POST", path="/login", status=302))
    alerts = run(BruteForceDetector(5, 300), evs)
    by = {a.rule_id: a for a in alerts}
    assert set(by) == {"BEH-BRUTE-FORCE", "BEH-BRUTE-SUCCESS"}
    s = by["BEH-BRUTE-SUCCESS"]
    assert s.severity == "critical"
    assert "5 failed" in s.detail
    assert len(s.evidence) <= 5


def test_brute_success_without_failures_no_alert():
    evs = [ev(0, method="POST", path="/login", status=200)]
    assert run(BruteForceDetector(5, 300), evs) == []
    evs = [ev(i, method="POST", path="/login", status=401) for i in range(4)]
    evs.append(ev(10, method="POST", path="/login", status=200))
    assert run(BruteForceDetector(5, 300), evs) == []


def test_login_path_matching():
    lp = ("/login", "/admin")
    assert is_login_path("/Login/", lp)
    assert is_login_path("/admin/users", lp)
    assert is_login_path("/admin?x=1", lp)
    assert not is_login_path("/administrator", lp)
    assert not is_login_path("/loginx", lp)


def test_brute_prefix_path_counts():
    evs = [ev(i, method="POST", path="/admin/login/", status=401) for i in range(3)]
    assert len(run(BruteForceDetector(3, 300), evs)) == 1  # under /admin
    evs = [ev(i, method="POST", path="/ADMIN/", status=401) for i in range(3)]
    assert len(run(BruteForceDetector(3, 300), evs)) == 1


def test_rate_spike():
    assert run(RateDetector(10, 60), [ev(i * 0.1, status=200) for i in range(9)]) == []
    alerts = run(RateDetector(10, 60), [ev(i * 0.1, status=200) for i in range(15)])
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.rule_id, a.severity, a.technique) == ("BEH-RATE-SPIKE", "low", "T1499")
    assert a.event_count == 15


def test_never_raises_on_odd_input():
    naive = LogEvent(timestamp=datetime(2025, 1, 1), client_ip="", method="-", path="",
                     query="", status=0, bytes_sent=0, referrer="", user_agent="")
    for det in (EnumerationDetector(), BruteForceDetector(), RateDetector()):
        det.feed(ev(0))
        det.feed(naive)
        det.feed(None)
        det.flush()
