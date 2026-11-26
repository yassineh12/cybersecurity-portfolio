import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import random
from datetime import datetime, timedelta, timezone

from watchtower.detectors.longhorizon import IdEnumerationDetector, LowAndSlowDetector, templatise
from watchtower.models import LogEvent

T0 = datetime(2024, 5, 1, 0, 0, tzinfo=timezone.utc)


def ev(sec, ip="203.0.113.5", path="/", status=200, method="GET"):
    return LogEvent(timestamp=T0 + timedelta(seconds=sec), client_ip=ip, method=method,
                    path=path, query="", status=status, bytes_sent=0, referrer="",
                    user_agent="", raw=f"{ip} {path} {status}")


def run(det, events):
    out = []
    for e in events:
        out += det.feed(e)
    return out + det.flush()


# ---- low and slow ----

def test_slow_404_walk_per_client():
    alerts = run(LowAndSlowDetector(), [ev(i * 300, path=f"/p{i}", status=404) for i in range(72)])
    assert [a.rule_id for a in alerts] == ["BEH-LOW-AND-SLOW"]
    a = alerts[0]
    assert a.technique == "T1595.003" and a.severity == "medium"
    assert a.client_ip == "203.0.113.5" and len(a.evidence) <= 5 and a.event_count >= 40


def test_slow_walk_over_ipv6_prefix():
    evs = [ev(i * 240, ip=f"2001:db8:1:2::{i % 40 + 1:x}", path=f"/x{i}", status=404) for i in range(90)]
    alerts = run(LowAndSlowDetector(), evs)
    assert len(alerts) == 1 and alerts[0].client_ip == "2001:db8:1:2::/64"
    assert "addresses" in alerts[0].detail


def test_network_needs_distinct_addresses():
    evs = [ev(i * 240, ip="2001:db8:1:2::1" if i % 2 else "2001:db8:1:2::2", path=f"/x{i}", status=404)
           for i in range(90)]
    alerts = run(LowAndSlowDetector(), evs)
    assert {a.client_ip for a in alerts} == {"2001:db8:1:2::1", "2001:db8:1:2::2"}  # per-client only


def test_lone_noisy_address_does_not_double_alert_network():
    evs = [ev(i * 240, ip="2001:db8:1:2::1", path=f"/x{i}", status=404) for i in range(90)]
    evs += [ev(i * 240 + 1, ip=f"2001:db8:1:2::{i + 10:x}", path="/ok") for i in range(4)]
    evs += [ev(i * 240 + 2, ip=f"2001:db8:1:2::{i + 20:x}", path="/q", status=404) for i in range(4)]
    alerts = run(LowAndSlowDetector(), evs)
    assert [a.client_ip for a in alerts] == ["2001:db8:1:2::1"]


def test_broken_images_stay_quiet():
    evs = [ev(i * 60, path=f"/page{i}") for i in range(200)]
    evs += [ev(i * 500, path=f"/img/{i}.png", status=404) for i in range(12)]
    assert run(LowAndSlowDetector(), sorted(evs, key=lambda e: e.timestamp)) == []


def test_crawler_five_percent_misses_stays_quiet():
    # 4 req/min for 24 h, 1 in 20 is a 404 on a distinct path: misses and paths
    # clear their thresholds in any 6 h window, only the ratio keeps it quiet
    evs = [ev(i * 15, ip="198.51.100.7", path=f"/c{i}", status=404 if i % 20 == 0 else 200)
           for i in range(5760)]
    assert run(LowAndSlowDetector(), evs) == []


def test_few_distinct_paths_stays_quiet():
    evs = [ev(i * 120, path="/favicon.ico", status=404) for i in range(150)]
    assert run(LowAndSlowDetector(), evs) == []


def test_slow_window_expires():
    # 72 misses spread over 3 days: never 40 in one 6 h window
    evs = [ev(i * 3600, path=f"/p{i}", status=404) for i in range(72)]
    assert run(LowAndSlowDetector(), evs) == []


def test_lowandslow_memory_cleanup():
    det = LowAndSlowDetector()
    for i in range(3000):  # one-off visitors, an hour apart
        det.feed(ev(i * 3600, ip=f"10.{i // 256 % 256}.{i % 256}.9", path="/a", status=404))
    assert len(det._states) <= 1024  # swept every 1024 events; 3000 visitors never accumulate
    det.flush()
    assert det._states == {}


def test_lowandslow_path_cap_counts_only():
    import watchtower.detectors.longhorizon as lh
    old = lh.PATH_CAP
    lh.PATH_CAP = 10
    try:
        det = LowAndSlowDetector(min_misses=5, min_distinct_paths=15)
        alerts = run(det, [ev(i * 10, path=f"/p{i}", status=404) for i in range(30)])
    finally:
        lh.PATH_CAP = old
    assert len(alerts) == 1  # paths beyond the cap are still counted


def test_lowandslow_never_raises_on_odd_events():
    det = LowAndSlowDetector()
    odd = LogEvent(timestamp=T0, client_ip="not-an-ip", method="-", path="", query="",
                   status=404, bytes_sent=0, referrer="", user_agent="")
    assert det.feed(odd) == [] and det.feed(None) == []  # type: ignore[arg-type]
    det.flush()


# ---- id enumeration ----

def test_templatise():
    assert templatise("/invoice/1042") == ("/invoice/{id}", 1042)
    assert templatise("/item/SKU10234") == ("/item/sku{id}", 10234)
    assert templatise("/inv/INV-00042/pdf") == ("/inv/inv-{id}/pdf", 42)
    assert templatise("/about") is None and templatise("") is None
    assert templatise("/a/99999999999999999999999") is None


def test_sequential_walk_raises_alert():
    evs = [ev(i * 300, path=f"/invoice/{1000 + i}", status=200 if i % 3 else 403) for i in range(61)]
    alerts = run(IdEnumerationDetector(), evs)
    assert len(alerts) == 1 and alerts[0].rule_id == "BEH-ID-ENUM"
    d = alerts[0].detail
    assert "/invoice/{id}" in d and "1000" in d and "non-2xx" in d
    assert alerts[0].technique == "T1595.003" and len(alerts[0].evidence) <= 5


def test_random_shopper_stays_quiet():
    rnd = random.Random(1)
    evs = [ev(i * 300, path=f"/product/{rnd.randint(1, 100000)}") for i in range(30)]
    assert run(IdEnumerationDetector(), evs) == []


def test_random_ids_many_stay_quiet():
    rnd = random.Random(2)
    evs = [ev(i * 60, path=f"/product/{rnd.randint(1, 1_000_000)}") for i in range(300)]
    assert run(IdEnumerationDetector(), evs) == []


def test_own_orders_stay_quiet():
    evs = [ev(i * 30, path=f"/orders/{5000 + i}") for i in range(10)]
    assert run(IdEnumerationDetector(), evs) == []


def test_repeated_ids_do_not_count():
    evs = [ev(i * 10, path=f"/orders/{5000 + i % 5}") for i in range(200)]
    assert run(IdEnumerationDetector(), evs) == []


def test_id_walk_over_network():
    evs = [ev(i * 120, ip=f"2001:db8:9:9::{i % 8 + 1:x}", path=f"/user/{300 + i}") for i in range(40)]
    alerts = run(IdEnumerationDetector(), evs)
    assert len(alerts) == 1 and alerts[0].client_ip == "2001:db8:9:9::/64"


def test_id_enum_window_expires():
    evs = [ev(i * 3600, path=f"/invoice/{i}") for i in range(60)]
    assert run(IdEnumerationDetector(), evs) == []


def test_id_enum_memory_cleanup_and_malformed():
    det = IdEnumerationDetector()
    for i in range(3000):
        det.feed(ev(i * 3600, ip=f"10.{i // 256 % 256}.{i % 256}.9", path=f"/o/{i}"))
    assert len(det._states) <= 1024  # swept every 1024 events; 3000 visitors never accumulate
    bad = LogEvent(timestamp=T0, client_ip="x", method="-", path="\x00//%%/{id}/999999999999999999999999",
                   query="", status=0, bytes_sent=0, referrer="", user_agent="")
    assert det.feed(bad) == [] and det.feed(None) == []  # type: ignore[arg-type]
    det.flush()
    assert det._states == {}
