import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import re
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from watchtower import engine
from watchtower.config import Config, config_from_dict
from watchtower.engine import _reorder, filter_min_severity, run
from watchtower.models import Alert, LogEvent

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
STAT_KEYS = {"lines_read", "lines_parsed", "lines_malformed", "events_allowlisted",
             "unique_clients", "time_start", "time_end", "files", "alerts_by_rule",
             "incidents_by_severity", "read_errors", "network_incidents"}

# --- a tiny combined-format parser so these tests do not depend on parsers.py ---
_LINE = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"')


@dataclass
class FakeStats:
    lines_read: int = 0
    lines_parsed: int = 0
    lines_malformed: int = 0


def fake_parse_file(path, fmt="auto"):
    stats = FakeStats()

    def gen():
        for n, line in enumerate(Path(path).read_text().splitlines(), 1):
            stats.lines_read += 1
            m = _LINE.match(line)
            if not m:
                stats.lines_malformed += 1
                continue
            stats.lines_parsed += 1
            ip, ts, method, target, status, size, ref, ua = m.groups()
            path_, _, query = target.partition("?")
            yield LogEvent(timestamp=datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc),
                           client_ip=ip, method=method, path=path_, query=query, status=int(status),
                           bytes_sent=0 if size == "-" else int(size), referrer="" if ref == "-" else ref,
                           user_agent="" if ua == "-" else ua, source=Path(path).name, line_no=n, raw=line)
    return gen(), stats


def line(ip, second, target="/", status=200, ua="Mozilla/5.0"):
    ts = (T0 + timedelta(seconds=second)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "GET {target} HTTP/1.1" {status} 100 "-" "{ua}"'


def write_log(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n")
    return p


# --- fake detectors ---

class Recorder:
    """Remembers every event; flags any client that requested /evil."""
    rule_ids = ("SIG-SQLI",)

    def __init__(self):
        self.seen: list[LogEvent] = []
        self.flushed = 0

    def feed(self, event):
        self.seen.append(event)
        return []

    def flush(self):
        self.flushed += 1
        out = {}
        for e in self.seen:
            if e.path == "/evil":
                a = out.setdefault(e.client_ip, Alert("SIG-SQLI", "SQLi", "high", e.client_ip, e.timestamp,
                                                      e.timestamp, 0, "T1190"))
                a.event_count += 1
                a.last_seen = e.timestamp
        return list(out.values())


class Immediate:
    """Emits from feed() rather than flush(), for a rule we may disable."""
    rule_ids = ("BEH-RATE-SPIKE",)

    def feed(self, event):
        return [Alert("BEH-RATE-SPIKE", "Rate", "low", event.client_ip, event.timestamp,
                      event.timestamp, 1, "T1499")]

    def flush(self):
        return []


class Exploding:
    rule_ids = ("SIG-XSS",)

    def feed(self, event):
        raise RuntimeError("boom")

    def flush(self):
        raise RuntimeError("boom")


@pytest.fixture
def fake_parser(monkeypatch):
    monkeypatch.setattr(engine, "_parse_file", fake_parse_file)


# --- tests ---

def test_merges_files_in_timestamp_order(tmp_path, fake_parser):
    a = write_log(tmp_path, "a.log", [line("192.0.2.1", s) for s in (0, 4, 8)])
    b = write_log(tmp_path, "b.log", [line("192.0.2.2", s) for s in (2, 6, 10)])
    rec = Recorder()
    run([a, b], Config(), detectors=[rec])
    assert [e.timestamp for e in rec.seen] == sorted(e.timestamp for e in rec.seen)
    assert [e.client_ip[-1] for e in rec.seen] == list("121212")
    assert rec.flushed == 1


def test_sorts_out_of_order_lines_within_a_file(tmp_path, fake_parser):
    p = write_log(tmp_path, "x.log", [line("192.0.2.1", s) for s in (5, 1, 3, 2, 4)])
    rec = Recorder()
    run([p], Config(), detectors=[rec])
    assert [e.line_no for e in rec.seen] == [2, 4, 3, 5, 1]


def test_reorder_buffer_is_bounded():
    events = [LogEvent(T0 + timedelta(seconds=s), "192.0.2.1", "GET", "/", "", 200, 0, "", "")
              for s in (3, 2, 1, 0)]
    # window 1: only adjacent disorder is fixed, the rest streams through late
    out = [int((e.timestamp - T0).total_seconds()) for e in _reorder(events, window=1)]
    assert sorted(out) == [0, 1, 2, 3] and out != [0, 1, 2, 3]
    assert [int((e.timestamp - T0).total_seconds()) for e in _reorder(events)] == [0, 1, 2, 3]


def test_allowlist_drops_events_before_detection(tmp_path, fake_parser):
    p = write_log(tmp_path, "x.log", [line("192.0.2.10", 0, "/evil"), line("192.0.2.10", 1),
                                      line("198.51.100.3", 2, "/evil"), line("203.0.113.9", 3, "/evil")])
    cfg = config_from_dict({"allowlist": ["192.0.2.10", "198.51.100.0/24"]})
    rec = Recorder()
    result = run([p], cfg, detectors=[rec])
    assert {e.client_ip for e in rec.seen} == {"203.0.113.9"}
    assert result.stats["events_allowlisted"] == 3
    assert result.stats["unique_clients"] == 1
    assert [i.client_ip for i in result.incidents] == ["203.0.113.9"]


def test_stats_filled_per_brief(tmp_path, fake_parser):
    a = write_log(tmp_path, "a.log", [line("192.0.2.1", 0, "/evil"), "garbage line", line("192.0.2.2", 30)])
    b = write_log(tmp_path, "b.log", [line("192.0.2.1", 60, "/evil"), line("192.0.2.3", 90)])
    result = run([a, b], Config(), detectors=[Recorder()])
    st = result.stats
    assert set(st) == STAT_KEYS
    assert (st["lines_read"], st["lines_parsed"], st["lines_malformed"]) == (5, 4, 1)
    assert st["unique_clients"] == 3 and st["events_allowlisted"] == 0
    assert st["time_start"] == T0.isoformat()
    assert st["time_end"] == (T0 + timedelta(seconds=90)).isoformat()
    assert st["files"] == [str(a), str(b)]
    assert st["alerts_by_rule"] == {"SIG-SQLI": 1}
    assert st["incidents_by_severity"] == {"low": 0, "medium": 0, "high": 1, "critical": 0}
    assert st["read_errors"] == []
    assert st["network_incidents"] == 0
    (alert,) = result.alerts
    assert alert.event_count == 2                     # one alert across both files
    assert result.generated_at.tzinfo is not None


def test_empty_input(tmp_path, fake_parser):
    p = write_log(tmp_path, "empty.log", [])
    result = run([p], Config(), detectors=[Recorder()])
    assert result.incidents == [] and result.alerts == []
    assert result.stats["time_start"] is None and result.stats["time_end"] is None
    assert result.stats["unique_clients"] == 0


def test_disabled_rules_filtered_even_for_injected_detectors(tmp_path, fake_parser):
    p = write_log(tmp_path, "x.log", [line("192.0.2.1", 0, "/evil")])
    cfg = config_from_dict({"rules": {"BEH-RATE-SPIKE": False}})
    result = run([p], cfg, detectors=[Immediate(), Recorder()])
    assert {a.rule_id for a in result.alerts} == {"SIG-SQLI"}


def test_buggy_detector_does_not_kill_the_scan(tmp_path, fake_parser):
    p = write_log(tmp_path, "x.log", [line("192.0.2.1", 0, "/evil")])
    with pytest.warns(RuntimeWarning, match="boom"):
        result = run([p], Config(), detectors=[Exploding(), Recorder()])
    assert len(result.incidents) == 1


def test_missing_file_raises_clear_error(tmp_path, fake_parser):
    with pytest.raises(FileNotFoundError, match="nope.log"):
        run([tmp_path / "nope.log"], Config(), detectors=[])


def test_alerts_sorted_and_incidents_by_score(tmp_path, fake_parser):
    p = write_log(tmp_path, "x.log", [line("192.0.2.2", 5, "/evil"), line("192.0.2.1", 1)])
    result = run([p], Config(), detectors=[Immediate(), Recorder()])
    assert [a.first_seen for a in result.alerts] == sorted(a.first_seen for a in result.alerts)
    assert [i.score for i in result.incidents] == sorted((i.score for i in result.incidents), reverse=True)
    assert result.incidents[0].client_ip == "192.0.2.2"


def test_filter_min_severity_keeps_report_consistent(tmp_path, fake_parser):
    p = write_log(tmp_path, "x.log", [line("192.0.2.2", 5, "/evil"), line("192.0.2.1", 1)])
    result = run([p], Config(), detectors=[Immediate(), Recorder()])
    shown = filter_min_severity(result, "high")
    assert [i.client_ip for i in shown.incidents] == ["192.0.2.2"]
    assert {a.client_ip for a in shown.alerts} == {"192.0.2.2"}
    assert shown.stats["incidents_by_severity"]["low"] == 0
    assert shown.stats["lines_read"] == result.stats["lines_read"]
    assert len(result.incidents) == 2                 # original untouched


def test_default_config_and_detectors_used_when_omitted(tmp_path, fake_parser, monkeypatch):
    import watchtower.detectors as dets
    calls = []
    monkeypatch.setattr(dets, "default_detectors", lambda cfg: calls.append(cfg) or [Recorder()])
    p = write_log(tmp_path, "x.log", [line("192.0.2.1", 0)])
    run([p])
    assert len(calls) == 1 and calls[0].source.endswith("default.yaml")


def test_end_to_end_with_real_parser_and_detectors(tmp_path):
    pytest.importorskip("watchtower.parsers")
    pytest.importorskip("watchtower.detectors.signatures")
    pytest.importorskip("watchtower.detectors.behaviour")
    ip = "203.0.113.5"
    lines = [line("192.0.2.20", s, f"/page{s}") for s in range(5)]
    lines += [line(ip, 10 + s, f"/probe{s}", 404, "Mozilla/5.00 (Nikto/2.1.6)") for s in range(3)]
    lines += [line(ip, 20, "/item?id=1%27%20OR%201=1--", 200, "Mozilla/5.00 (Nikto/2.1.6)")]
    lines += [line("192.0.2.10", 30, "/.env", 404, "uptime-bot")]
    p = write_log(tmp_path, "access.log", lines)
    cfg = config_from_dict({"allowlist": ["192.0.2.10"]})
    result = run([p], cfg)
    assert result.stats["events_allowlisted"] == 1
    top = result.incidents[0]
    assert top.client_ip == ip
    assert {"SIG-UA-SCANNER", "SIG-SQLI"} <= {a.rule_id for a in top.alerts}
    assert top.stages[:2] == ["recon", "exploit"]
    assert top.severity == "critical"
    assert "192.0.2.10" not in {i.client_ip for i in result.incidents}
    assert "192.0.2.20" not in {i.client_ip for i in result.incidents}


# --- config (config.py has no test file of its own; it is part of the engine) ---

from watchtower.config import ConfigError, KNOWN_RULES, load_config  # noqa: E402


def test_default_yaml_matches_brief_and_builtin_defaults():
    cfg = load_config(None)
    builtin = Config()
    assert cfg.detectors == builtin.detectors
    assert cfg.scoring == builtin.scoring
    assert cfg.allowlist == ()                       # the example entry ships commented out
    assert all(cfg.rule_enabled(r) for r in KNOWN_RULES)
    assert cfg.detector_options("enumeration") == {"threshold": 20, "window_seconds": 60,
                                                   "slow_threshold": 100, "slow_window_seconds": 900,
                                                   "ipv6_prefix": 64, "ipv4_prefix": None,
                                                   "min_distinct": 4}
    for name in ("brute_force", "rate"):
        opts = cfg.detector_options(name)
        assert (opts["ipv6_prefix"], opts["ipv4_prefix"], opts["min_distinct"]) == (64, None, 4)
    assert "ipv6_prefix" not in cfg.detector_options("signatures")
    paths = cfg.detector_options("brute_force")["login_paths"]
    assert "/admin/login" in paths and "/xmlrpc.php" in paths and "/api/login" in paths
    assert cfg.detector_options("brute_force")["threshold"] == 10
    assert cfg.detector_options("brute_force")["window_seconds"] == 300
    assert (cfg.detector_options("rate")["threshold"], cfg.detector_options("rate")["window_seconds"]) == (300, 60)
    assert "192.0.2.10" in Path(cfg.source).read_text() and "your uptime monitor" in Path(cfg.source).read_text()


def test_allowlist_ips_cidrs_and_garbage():
    cfg = config_from_dict({"allowlist": ["192.0.2.10", "198.51.100.0/24", "2001:db8::/32"]})
    assert cfg.is_allowlisted("192.0.2.10")
    assert not cfg.is_allowlisted("192.0.2.11")
    assert cfg.is_allowlisted("198.51.100.200")
    assert cfg.is_allowlisted("2001:db8::1")
    assert cfg.is_allowlisted("::ffff:192.0.2.10")
    assert not cfg.is_allowlisted("not-an-ip")
    assert not cfg.is_allowlisted("")


def test_partial_config_file_merges_over_defaults(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("detectors:\n  enumeration:\n    threshold: 50\n  rate:\n    enabled: false\n"
                 "rules:\n  SIG-XSS: false\n")
    cfg = load_config(p)
    assert cfg.detector_options("enumeration")["threshold"] == 50
    assert cfg.detector_options("enumeration")["window_seconds"] == 60
    assert not cfg.detector_enabled("rate") and cfg.detector_enabled("signatures")
    assert not cfg.rule_enabled("SIG-XSS") and cfg.rule_enabled("SIG-SQLI")


def test_empty_config_file_is_defaults(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("")
    assert load_config(p).detectors == Config().detectors


@pytest.mark.parametrize("text, message", [
    ("allowlist: [999.1.1.1]", "not an IP address"),
    ("allowlist: [0.0.0.0/0]", "whole Internet"),
    ("allowlist: 192.0.2.1", "must be a list"),
    ("detectors:\n  enumeration:\n    threshhold: 5", "did you mean 'threshold'"),
    ("detectors:\n  enumeration:\n    threshold: 0", "positive integer"),
    ("detectors:\n  enumeration:\n    threshold: yes", "positive integer"),
    ("detectors:\n  signature: {}", "did you mean 'signatures'"),
    ("detectors:\n  brute_force:\n    login_paths: [login]", "starting with '/'"),
    ("rules:\n  SIG-SQL: false", "did you mean 'SIG-SQLI'"),
    ("rules:\n  SIG-SQLI: maybe", "true or false"),
    ("scoring:\n  severity_points: {high: 500}", "at most 100"),
    ("detectors:\n  enumeration:\n    ipv6_prefix: 16", "from 32 to 128"),
    ("detectors:\n  rate:\n    ipv6_prefix: 129", "from 32 to 128"),
    ("detectors:\n  rate:\n    ipv6_prefix: null", "from 32 to 128"),
    ("detectors:\n  brute_force:\n    ipv4_prefix: 4", "from 8 to 32 or null"),
    ("detectors:\n  brute_force:\n    ipv4_prefix: 33", "from 8 to 32 or null"),
    ("detectors:\n  enumeration:\n    min_distinct: 1", "at least 2"),
    ("detectors:\n  signatures:\n    ipv6_prefix: 64", "unknown key 'ipv6_prefix'"),
    ("detectors:\n  low_and_slow:\n    min_miss_ratio: 1.5", "at most 1"),
    ("detectors:\n  low_and_slow:\n    min_miss_ratio: 0", "above 0"),
    ("detectors:\n  id_enumeration:\n    max_step: 0", "positive integer"),
    ("detectors:\n  id_enumeration:\n    min_sequential: 2", "at most 1"),
    ("detectors:\n  id_enumeration:\n    min_id: 5", "did you mean 'min_ids'"),
    ("detectors:\n  brute_force:\n    login_keywords: login", "list of non-empty strings"),
    ("detectors:\n  brute_force:\n    login_keywords: [login, '']", "list of non-empty strings"),
    ("detectors:\n  brute_force:\n    path_agnostic_factor: -1", "positive integer"),
    ("detectors:\n  brute_force:\n    path_agnostic_factor: 2.5", "positive integer"),
    ("rules:\n  BEH-ID-ENUMS: false", "did you mean 'BEH-ID-ENUM'"),
    ("scoring:\n  severity_cutoffs: {high: 90}", "medium <= high <= critical"),
    ("allowlistt: []", "did you mean 'allowlist'"),
    ("- just a list", "top level must be a mapping"),
    ("detectors: [unclosed", "invalid YAML"),
])
def test_bad_config_gives_clear_error(tmp_path, text, message):
    p = tmp_path / "bad.yaml"
    p.write_text(text)
    with pytest.raises(ConfigError, match=re.escape(message)):
        load_config(p)


def test_missing_config_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")


# --- detectors/__init__.py registry ---

def test_default_detectors_builds_from_config_and_filters_rules(monkeypatch):
    import types
    import watchtower.detectors as dets

    built = {}

    def make(name, rules):
        class Fake:
            rule_ids = rules

            def __init__(self, **kw):
                built[name] = kw

            def feed(self, event):
                return [Alert(r, r, "low", event.client_ip, event.timestamp, event.timestamp, 1, "T0")
                        for r in rules]

            def flush(self):
                return []
        return Fake

    sig = types.ModuleType("fake_sig")
    sig.SignatureDetector = make("signatures", ("SIG-SQLI", "SIG-XSS"))
    beh = types.ModuleType("fake_beh")
    beh.EnumerationDetector = make("enumeration", ("BEH-404-BURST",))
    beh.BruteForceDetector = make("brute_force", ("BEH-BRUTE-FORCE", "BEH-BRUTE-SUCCESS"))
    beh.RateDetector = make("rate", ("BEH-RATE-SPIKE",))
    monkeypatch.setitem(sys.modules, "watchtower.detectors.signatures", sig)
    monkeypatch.setitem(sys.modules, "watchtower.detectors.behaviour", beh)

    cfg = config_from_dict({"detectors": {"rate": {"enabled": False}, "enumeration": {"threshold": 7},
                                          "low_and_slow": {"enabled": False},
                                          "id_enumeration": {"enabled": False}},
                            "rules": {"SIG-XSS": False, "BEH-BRUTE-FORCE": False, "BEH-BRUTE-SUCCESS": False}})
    detectors = dets.default_detectors(cfg)
    assert set(built) == {"signatures", "enumeration"}       # brute force: every rule off, never built
    assert built["enumeration"] == {"threshold": 7, "window_seconds": 60,
                                    "slow_threshold": 100, "slow_window_seconds": 900,
                                    "ipv6_prefix": 64, "ipv4_prefix": None, "min_distinct": 4}
    assert len(detectors) == 2                      # rate disabled, brute force has no rules left
    ev = LogEvent(T0, "192.0.2.1", "GET", "/", "", 200, 0, "", "")
    emitted = [a.rule_id for d in detectors for a in d.feed(ev)]
    assert emitted == ["SIG-SQLI", "BEH-404-BURST"]


def test_default_detectors_warns_on_missing_module(monkeypatch):
    import watchtower.detectors as dets
    monkeypatch.setitem(sys.modules, "watchtower.detectors.behaviour", None)   # import fails
    with pytest.warns(RuntimeWarning, match="unavailable"):
        detectors = dets.default_detectors(Config())
    assert all("behaviour" not in type(d.inner).__module__ for d in detectors)


def test_only_options_the_constructor_accepts_are_passed():
    from watchtower.detectors import _accepted_options

    class OldEnum:                                   # a detector without the slow window
        def __init__(self, threshold=20, window_seconds=60):
            pass

    defaults = Config()
    assert _accepted_options("enumeration", OldEnum, defaults) == {"threshold": 20, "window_seconds": 60}
    tuned = config_from_dict({"detectors": {"enumeration": {"slow_threshold": 50}}})
    with pytest.warns(RuntimeWarning, match="slow_threshold"):
        assert "slow_threshold" not in _accepted_options("enumeration", OldEnum, tuned)


# --- read errors (truncated .gz, I/O errors) ---

def test_read_error_mid_file_keeps_events_and_is_recorded(tmp_path, monkeypatch):
    good = write_log(tmp_path, "good.log", [line("192.0.2.1", 0, "/evil")])
    broken = write_log(tmp_path, "broken.log.gz", [line("192.0.2.2", 1, "/evil"), line("192.0.2.2", 2)])

    def parse(path, fmt="auto"):
        events, stats = fake_parse_file(path, fmt)
        if Path(path).name != "broken.log.gz":
            return events, stats

        def gen():
            yield next(events)
            raise EOFError("Compressed file ended before the end-of-stream marker was reached")
        return gen(), stats

    monkeypatch.setattr(engine, "_parse_file", parse)
    result = run([good, broken], Config(), detectors=[Recorder()])
    assert {i.client_ip for i in result.incidents} == {"192.0.2.1", "192.0.2.2"}
    (err,) = result.stats["read_errors"]
    assert err.startswith(f"{broken}: EOFError")


def test_parser_reported_read_error_is_used(tmp_path, monkeypatch):
    p = write_log(tmp_path, "x.log.gz", [line("192.0.2.1", 0)])

    def parse(path, fmt="auto"):
        events, stats = fake_parse_file(path, fmt)
        stats.read_error = "x.log.gz: BadGzipFile: Not a gzipped file (b'19')"   # parser's format
        return events, stats

    monkeypatch.setattr(engine, "_parse_file", parse)
    result = run([p], Config(), detectors=[])
    assert result.stats["read_errors"] == [f"{p}: BadGzipFile: Not a gzipped file (b'19')"]


def test_truncated_gzip_with_real_parser_does_not_raise(tmp_path):
    import gzip
    pytest.importorskip("watchtower.parsers")
    data = gzip.compress(("\n".join(line("192.0.2.1", s) for s in range(2000)) + "\n").encode())
    p = tmp_path / "cut.log.gz"
    p.write_bytes(data[: len(data) // 2])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = run([p], Config(), detectors=[Recorder()])
    (err,) = result.stats["read_errors"]
    assert err.startswith(f"{p}: ") and "cut.log.gz: cut.log.gz" not in err
    assert result.stats["lines_parsed"] > 0                 # what was readable still counts



# --- network channel (behaviour detectors group IPv6 /64s etc.) ---

def test_network_options_valid_values(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("detectors:\n  enumeration:\n    ipv6_prefix: 56\n    ipv4_prefix: 24\n"
                 "    min_distinct: 3\n  rate:\n    ipv4_prefix: null\n")
    cfg = load_config(p)
    opts = cfg.detector_options("enumeration")
    assert (opts["ipv6_prefix"], opts["ipv4_prefix"], opts["min_distinct"]) == (56, 24, 3)
    assert cfg.detector_options("rate")["ipv4_prefix"] is None


class PerNetwork:
    """Fake network channel: one alert per /64 once 2+ distinct addresses hit /evil."""
    rule_ids = ("BEH-404-BURST",)

    def __init__(self):
        self.addrs: dict[str, set[str]] = {}
        self.fed: list[str] = []

    def feed(self, event):
        import ipaddress
        self.fed.append(event.client_ip)
        if event.path == "/evil":
            net = str(ipaddress.ip_network(f"{event.client_ip}/64", strict=False))
            self.addrs.setdefault(net, set()).add(event.client_ip)
        return []

    def flush(self):
        return [Alert("BEH-404-BURST", "Burst", "medium", net, T0, T0, len(a), "T1595.003",
                      detail=f"distributed across {len(a)} addresses in {net}: ...")
                for net, a in self.addrs.items() if len(a) >= 2]


def test_allowlisted_addresses_never_reach_the_network_channel(tmp_path, fake_parser):
    lines = [line(f"2001:db8:abcd:12::{n}", n, "/evil") for n in range(1, 5)]
    p = write_log(tmp_path, "v6.log", lines)
    det = PerNetwork()
    # three of the four addresses are allowlisted: the /64 must not reach 2 distinct
    cfg = config_from_dict({"allowlist": ["2001:db8:abcd:12::1", "2001:db8:abcd:12::2/127",
                                          "2001:db8:abcd:12::3"]})
    result = run([p], cfg, detectors=[det])
    assert det.fed == ["2001:db8:abcd:12::4"]
    assert result.incidents == [] and result.stats["network_incidents"] == 0
    assert result.stats["events_allowlisted"] == 3
    # without the allowlist the same traffic is a network incident
    result = run([p], Config(), detectors=[PerNetwork()])
    assert [i.client_ip for i in result.incidents] == ["2001:db8:abcd:12::/64"]
    assert result.stats["network_incidents"] == 1
    assert filter_min_severity(result, "high").stats["network_incidents"] == 0


def test_allowlist_and_real_network_channel(tmp_path):
    import inspect
    pytest.importorskip("watchtower.parsers")
    beh = pytest.importorskip("watchtower.detectors.behaviour")
    if "ipv6_prefix" not in inspect.signature(beh.EnumerationDetector.__init__).parameters:
        pytest.skip("behaviour.py has no network channel yet")
    # 8 addresses of one /64, each 4 misses: below the per-address threshold (20),
    # 32 together: above it as a network.
    lines = [line(f"2001:db8:abcd:12::{a}", a * 4 + k, f"/x{a}{k}", 404) for a in range(1, 9) for k in range(4)]
    p = write_log(tmp_path, "v6.log", lines)
    flagged = run([p], load_config(None))
    assert "2001:db8:abcd:12::/64" in {i.client_ip for i in flagged.incidents}
    allow_all = config_from_dict({"allowlist": ["2001:db8:abcd:12::/64"]})
    quiet = run([p], allow_all)
    assert quiet.incidents == [] and quiet.stats["events_allowlisted"] == 32



# --- long-horizon detectors and new brute-force options ---

def test_long_horizon_defaults_and_optional_brute_force_options(tmp_path):
    cfg = load_config(None)
    assert cfg.detector_options("low_and_slow") == {
        "window_seconds": 21600, "min_misses": 40, "min_miss_ratio": 0.3, "min_distinct_paths": 20,
        "ipv6_prefix": 64, "ipv4_prefix": None, "min_distinct": 4}
    assert cfg.detector_options("id_enumeration") == {
        "window_seconds": 21600, "min_ids": 25, "max_step": 3, "min_sequential": 0.7,
        "ipv6_prefix": 64, "ipv4_prefix": None, "min_distinct": 4}
    assert cfg.rule_enabled("BEH-LOW-AND-SLOW") and cfg.rule_enabled("BEH-ID-ENUM")
    # optional options are absent unless set, so the detector's own default applies
    assert "login_keywords" not in cfg.detector_options("brute_force")
    p = tmp_path / "c.yaml"
    p.write_text("detectors:\n  brute_force:\n    login_keywords: [Login, ' signin ']\n"
                 "    path_agnostic_factor: 3\n  low_and_slow:\n    min_miss_ratio: 0.5\n")
    tuned = load_config(p)
    assert tuned.detector_options("brute_force")["login_keywords"] == ("login", "signin")
    assert tuned.detector_options("brute_force")["path_agnostic_factor"] == 3
    off = config_from_dict({"detectors": {"brute_force": {"login_keywords": []}}})
    assert off.detector_options("brute_force")["login_keywords"] == ()
    assert tuned.detector_options("low_and_slow")["min_miss_ratio"] == 0.5


def test_registry_builds_long_horizon_detectors(monkeypatch):
    import types
    import watchtower.detectors as dets
    built = {}

    def make(name, rule):
        class Fake:
            rule_ids = (rule,)

            def __init__(self, window_seconds=1, min_misses=1, min_ids=1):   # partial signature
                built[name] = dict(window_seconds=window_seconds)

            def feed(self, event):
                return []

            def flush(self):
                return []
        return Fake

    mod = types.ModuleType("fake_lh")
    mod.LowAndSlowDetector = make("low_and_slow", "BEH-LOW-AND-SLOW")
    mod.IdEnumerationDetector = make("id_enumeration", "BEH-ID-ENUM")
    monkeypatch.setitem(sys.modules, "watchtower.detectors.longhorizon", mod)
    cfg = config_from_dict({"rules": {"BEH-ID-ENUM": False}})
    names = [type(d.inner).__name__ for d in dets.default_detectors(cfg)]
    assert built == {"low_and_slow": {"window_seconds": 21600}}       # id_enumeration: rule off
    assert names.count("Fake") == 1


def test_missing_longhorizon_module_warns_and_scan_continues(monkeypatch):
    import watchtower.detectors as dets
    monkeypatch.setitem(sys.modules, "watchtower.detectors.longhorizon", None)
    with pytest.warns(RuntimeWarning, match="longhorizon"):
        detectors = dets.default_detectors(Config())
    assert detectors                                   # the other detectors still built


def test_optional_option_unsupported_by_detector_warns():
    from watchtower.detectors import _accepted_options

    class OldBrute:
        def __init__(self, threshold=10, window_seconds=300, login_paths=()):
            pass

    cfg = config_from_dict({"detectors": {"brute_force": {"path_agnostic_factor": 2}}})
    with pytest.warns(RuntimeWarning, match="path_agnostic_factor"):
        opts = _accepted_options("brute_force", OldBrute, cfg)
    assert "path_agnostic_factor" not in opts


def test_new_options_reach_the_real_detectors():
    pytest.importorskip("watchtower.detectors.longhorizon")
    import inspect
    from watchtower.detectors import default_detectors
    from watchtower.detectors.behaviour import BruteForceDetector
    if "path_agnostic_factor" not in inspect.signature(BruteForceDetector.__init__).parameters:
        pytest.skip("behaviour.py without path_agnostic_factor")
    cfg = config_from_dict({"detectors": {"brute_force": {"path_agnostic_factor": 5},
                                          "id_enumeration": {"min_ids": 30}}})
    with warnings.catch_warnings():
        warnings.simplefilter("error")                      # nothing dropped or unknown
        dets = {type(d.inner).__name__: d.inner for d in default_detectors(cfg)}
    assert {"LowAndSlowDetector", "IdEnumerationDetector", "BruteForceDetector"} <= set(dets)
    assert dets["IdEnumerationDetector"].min_ids == 30
