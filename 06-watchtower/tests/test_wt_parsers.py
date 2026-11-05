import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gzip
import json
from datetime import timedelta, timezone

from watchtower.parsers import ParseStats, parse_file, parse_line

COMBINED = ('203.0.113.9 - bob [10/Oct/2000:13:55:36 -0700] "GET /a%20b/x.php?id=1%27 HTTP/1.1" '
            '200 2326 "http://ref.example/" "Mozilla/5.0"')
COMMON = '203.0.113.9 - - [10/Oct/2000:13:55:36 +0000] "POST /login HTTP/1.1" 401 -'


def test_combined():
    e = parse_line(COMBINED, source="a.log", line_no=7)
    assert (e.client_ip, e.method, e.status, e.bytes_sent) == ("203.0.113.9", "GET", 200, 2326)
    assert e.path == "/a b/x.php" and e.query == "id=1%27"
    assert e.referrer == "http://ref.example/" and e.user_agent == "Mozilla/5.0"
    assert e.source == "a.log" and e.line_no == 7 and e.raw == COMBINED


def test_common_and_dash_bytes():
    e = parse_line(COMMON, "common")
    assert e.method == "POST" and e.bytes_sent == 0 and e.referrer == "" and e.user_agent == ""


def test_common_rejects_nothing_in_combined_mode_for_common_line():
    assert parse_line(COMMON, "combined") is None
    assert parse_line(COMMON, "auto") is not None


def test_timezone_to_utc():
    e = parse_line(COMBINED)
    assert e.timestamp.utcoffset() == timedelta(0)
    assert (e.timestamp.hour, e.timestamp.day) == (20, 10)
    e2 = parse_line('1.2.3.4 - - [10/Oct/2000:01:00:00 +0200] "GET / HTTP/1.1" 200 1')
    assert (e2.timestamp.day, e2.timestamp.hour) == (9, 23)
    assert e2.timestamp.tzinfo == timezone.utc


def test_ipv6():
    e = parse_line('2001:db8::1 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "-"')
    assert e.client_ip == "2001:db8::1" and e.user_agent == ""


def test_escaped_quotes():
    line = ('1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET /x?q=\\"a\\" HTTP/1.1" 200 5 '
            '"-" "Evil \\"agent\\" 1.0"')
    e = parse_line(line)
    assert e.user_agent == 'Evil "agent" 1.0'
    assert e.query == 'q="a"'


def test_garbage_and_dash_requests():
    for req in ("-", "\\x16\\x03\\x01", "GARBAGE"):
        e = parse_line(f'1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "{req}" 400 0 "-" "-"')
        assert e is not None and e.method == "-" and e.path == "" and e.query == ""


def test_double_encoding_decoded_once():
    e = parse_line('1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET /%252e%252e/etc HTTP/1.1" 404 0 "-" "-"')
    assert e.path == "/%2e%2e/etc"


def test_jsonl_iso_and_request():
    rec = {"time": "2024-05-01T12:00:00+02:00", "remote_addr": "198.51.100.4",
           "request": "GET /p?x=1 HTTP/1.1", "status": 404, "body_bytes_sent": 12,
           "http_referer": "-", "http_user_agent": "curl/8"}
    e = parse_line(json.dumps(rec), "jsonl")
    assert e.timestamp.hour == 10 and e.path == "/p" and e.query == "x=1"
    assert e.status == 404 and e.bytes_sent == 12 and e.referrer == "" and e.user_agent == "curl/8"


def test_jsonl_method_uri_time_local():
    rec = {"time_local": "10/Oct/2000:13:55:36 -0700", "remote_addr": "::1", "method": "post",
           "uri": "/a%2Fb?z=2", "status": "200"}
    e = parse_line(json.dumps(rec))  # auto detects "{"
    assert e.method == "POST" and e.path == "/a/b" and e.query == "z=2" and e.timestamp.hour == 20


def test_jsonl_bad():
    for bad in ("{not json", "[1,2]", '{"remote_addr": "1.1.1.1"}', '{"time":"nope","remote_addr":"1.1.1.1"}'):
        assert parse_line(bad, "jsonl") is None


def test_malformed_never_raises():
    for bad in ("", "   ", "hello world", "\x00\xff� junk", '1.2.3.4 - - [bad date] "GET / HTTP/1.1" 200 1',
                "{" * 500):
        assert parse_line(bad) is None


def test_binary_junk_in_agent_ok():
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "�\x01�"'
    assert parse_line(line).user_agent == "�\x01�"


def test_parse_file_stats_line_numbers_and_junk(tmp_path):
    p = tmp_path / "access.log"
    p.write_bytes(COMBINED.encode() + b"\n\xff\xfe\x00garbage\n\n" + COMBINED.encode() + b"\n")
    it, stats = parse_file(p)
    assert isinstance(stats, ParseStats) and stats.lines_read == 0
    events = list(it)
    assert [e.line_no for e in events] == [1, 4]
    assert all(e.source == "access.log" for e in events)
    assert (stats.lines_read, stats.lines_parsed, stats.lines_malformed) == (3, 2, 1)


def test_parse_file_gzip_and_mixed_auto(tmp_path):
    p = tmp_path / "mixed.log.gz"
    js = json.dumps({"time": "2024-05-01T00:00:00Z", "remote_addr": "1.1.1.1", "request": "GET / HTTP/1.1", "status": 200})
    with gzip.open(p, "wt") as f:
        f.write("\n".join([COMBINED, COMMON, js, "bad"]) + "\n")
    it, stats = parse_file(p)
    assert len(list(it)) == 3 and stats.lines_malformed == 1


def test_parse_file_is_lazy(tmp_path):
    p = tmp_path / "l.log"
    p.write_text((COMBINED + "\n") * 5)
    it, stats = parse_file(p, "combined")
    next(it)
    assert stats.lines_read == 1
