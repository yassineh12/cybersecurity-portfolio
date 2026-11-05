from analyser import (
    parse_line,
    detect_sqli,
    detect_xss,
    detect_traversal,
    detect_brute_force,
    detect_scanner_agents,
    detect_sensitive_probing,
    detect_high_error_rate,
    is_internal_ip,
    compute_temporal,
    LogEntry,
)


NORMAL_LINE = '192.168.1.1 - - [03/Nov/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
SQLI_LINE = '10.0.0.5 - - [03/Nov/2026:10:15:33 +0000] "GET /search?q=1%27%20OR%201%3D1 HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
XSS_LINE = '10.0.0.5 - - [03/Nov/2026:10:15:34 +0000] "GET /page?name=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 600 "-" "Mozilla/5.0"'
TRAVERSAL_LINE = '10.0.0.5 - - [03/Nov/2026:10:15:35 +0000] "GET /files/../../../etc/passwd HTTP/1.1" 403 0 "-" "Mozilla/5.0"'
SCANNER_LINE = '10.0.0.5 - - [03/Nov/2026:10:15:36 +0000] "GET /admin HTTP/1.1" 404 0 "-" "Nikto/2.1.6"'


def test_parse_normal_line():
    entry = parse_line(NORMAL_LINE)
    assert entry is not None
    assert entry.ip == "192.168.1.1"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.status == 200


def test_parse_invalid_line():
    assert parse_line("this is not a log line") is None
    assert parse_line("") is None


def test_detect_sqli():
    entry = parse_line(SQLI_LINE)
    alerts = detect_sqli({"10.0.0.5": [entry]})
    assert any(a.rule_id == "sqli-attempt" for a in alerts)


def test_detect_xss():
    entry = parse_line(XSS_LINE)
    alerts = detect_xss({"10.0.0.5": [entry]})
    assert any(a.rule_id == "xss-attempt" for a in alerts)


def test_detect_traversal():
    entry = parse_line(TRAVERSAL_LINE)
    alerts = detect_traversal({"10.0.0.5": [entry]})
    assert any(a.rule_id == "path-traversal" for a in alerts)


def test_detect_scanner_agent():
    entry = parse_line(SCANNER_LINE)
    alerts = detect_scanner_agents({"10.0.0.5": [entry]})
    assert any(a.rule_id == "scanner-agent" for a in alerts)


def test_detect_brute_force():
    entries = []
    for i in range(15):
        e = LogEntry(
            ip="10.0.0.5", timestamp="", method="POST",
            path="/login", status=401, size=0,
            referer="", user_agent="Mozilla/5.0", raw=""
        )
        entries.append(e)
    alerts = detect_brute_force({"10.0.0.5": entries})
    assert any(a.rule_id == "brute-force" for a in alerts)


def test_no_false_brute_force():
    entries = [LogEntry(
        ip="10.0.0.5", timestamp="", method="GET",
        path="/about", status=200, size=100,
        referer="", user_agent="Mozilla/5.0", raw=""
    )]
    alerts = detect_brute_force({"10.0.0.5": entries})
    assert len(alerts) == 0


def test_sensitive_probing():
    paths = ["/admin", "/.env", "/.git/HEAD", "/phpmyadmin"]
    entries = [LogEntry(
        ip="10.0.0.5", timestamp="", method="GET",
        path=p, status=404, size=0,
        referer="", user_agent="Mozilla/5.0", raw=""
    ) for p in paths]
    alerts = detect_sensitive_probing({"10.0.0.5": entries})
    assert any(a.rule_id == "sensitive-probing" for a in alerts)


def test_normal_traffic_no_alerts():
    entry = parse_line(NORMAL_LINE)
    all_alerts = (
        detect_sqli({"192.168.1.1": [entry]})
        + detect_xss({"192.168.1.1": [entry]})
        + detect_traversal({"192.168.1.1": [entry]})
        + detect_scanner_agents({"192.168.1.1": [entry]})
    )
    assert len(all_alerts) == 0


def test_internal_ip_rfc1918():
    assert is_internal_ip("10.0.0.1") is True
    assert is_internal_ip("192.168.1.100") is True
    assert is_internal_ip("172.16.0.5") is True
    assert is_internal_ip("172.31.255.255") is True
    assert is_internal_ip("127.0.0.1") is True


def test_external_ip():
    assert is_internal_ip("8.8.8.8") is False
    assert is_internal_ip("203.0.113.1") is False
    assert is_internal_ip("172.32.0.1") is False


def test_custom_brute_threshold():
    entries = [LogEntry(
        ip="10.0.0.5", timestamp="", method="POST",
        path="/login", status=401, size=0,
        referer="", user_agent="Mozilla/5.0", raw=""
    ) for _ in range(5)]
    alerts_default = detect_brute_force({"10.0.0.5": entries}, threshold=10)
    assert len(alerts_default) == 0
    alerts_low = detect_brute_force({"10.0.0.5": entries}, threshold=3)
    assert any(a.rule_id == "brute-force" for a in alerts_low)


def test_custom_scan_threshold():
    entries = [LogEntry(
        ip="10.0.0.5", timestamp="", method="GET",
        path=f"/path{i}", status=404, size=0,
        referer="", user_agent="Mozilla/5.0", raw=""
    ) for i in range(30)]
    alerts_default = detect_high_error_rate({"10.0.0.5": entries}, threshold=50)
    assert len(alerts_default) == 0
    alerts_low = detect_high_error_rate({"10.0.0.5": entries}, threshold=20)
    assert any(a.rule_id == "directory-scan" for a in alerts_low)


def test_mitre_mapping_on_alerts():
    entry = parse_line(SCANNER_LINE)
    alerts = detect_scanner_agents({"10.0.0.5": [entry]})
    scanner_alert = [a for a in alerts if a.rule_id == "scanner-agent"]
    assert scanner_alert
    assert scanner_alert[0].mitre_technique == "T1595.002"
    assert scanner_alert[0].mitre_tactic == "Reconnaissance"


def test_mitre_mapping_sqli():
    entry = parse_line(SQLI_LINE)
    alerts = detect_sqli({"10.0.0.5": [entry]})
    sqli = [a for a in alerts if a.rule_id == "sqli-attempt"]
    assert sqli
    assert sqli[0].mitre_technique == "T1190"


def test_temporal_analysis():
    entries = [
        LogEntry(ip="1.2.3.4", timestamp="03/Nov/2026:10:15:32 +0000",
                 method="GET", path="/", status=200, size=100,
                 referer="", user_agent="", raw=""),
        LogEntry(ip="1.2.3.4", timestamp="03/Nov/2026:10:45:00 +0000",
                 method="GET", path="/a", status=200, size=100,
                 referer="", user_agent="", raw=""),
        LogEntry(ip="1.2.3.4", timestamp="03/Nov/2026:11:00:00 +0000",
                 method="GET", path="/b", status=200, size=100,
                 referer="", user_agent="", raw=""),
    ]
    hourly = compute_temporal({"1.2.3.4": entries})
    assert hourly.get("2026-11-03 10:00") == 2
    assert hourly.get("2026-11-03 11:00") == 1


def test_empty_log_no_alerts():
    entries_by_ip: dict[str, list[LogEntry]] = {}
    assert detect_sqli(entries_by_ip) == []
    assert detect_xss(entries_by_ip) == []
    assert detect_brute_force(entries_by_ip) == []
    assert detect_scanner_agents(entries_by_ip) == []
    assert detect_traversal(entries_by_ip) == []
