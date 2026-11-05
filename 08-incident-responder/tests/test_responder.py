from responder import (
    VERSION,
    build_response,
    detect_from_logs,
    extract_iocs,
    generate_firewall_rules,
    generate_recommendations,
    generate_yara_rules,
    build_timeline,
    firewall_to_iptables,
    yara_to_text,
    to_markdown,
    to_stix,
    severity_score,
    parse_log_line,
    IOC,
)


SAMPLE_LOG = (
    '198.51.100.7 - - [27/Oct/2026:23:41:08 +0000] '
    '"GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" '
    '200 4891 "-" "Nikto/2.1.6"'
)

BRUTE_LOG_TEMPLATE = (
    '203.0.113.42 - - [27/Oct/2026:22:14:{sec:02d} +0000] '
    '"POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"'
)

XSS_LOG = (
    '10.0.0.5 - - [27/Oct/2026:23:38:52 +0000] '
    '"GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" '
    '200 3204 "-" "Mozilla/5.0"'
)

TRAVERSAL_LOG = (
    '10.0.0.5 - - [27/Oct/2026:23:39:44 +0000] '
    '"GET /download?file=../../../../etc/passwd HTTP/1.1" '
    '400 0 "-" "Mozilla/5.0"'
)

CLEAN_LOG = (
    '192.168.1.1 - - [27/Oct/2026:12:00:00 +0000] '
    '"GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
)


def test_parse_log_line():
    parsed = parse_log_line(SAMPLE_LOG)
    assert parsed is not None
    assert parsed["ip"] == "198.51.100.7"
    assert parsed["method"] == "GET"
    assert parsed["status"] == "200"
    assert "Nikto" in parsed["ua"]


def test_parse_invalid_line():
    assert parse_log_line("not a log line") is None
    assert parse_log_line("") is None


def test_detect_scanner():
    alerts = detect_from_logs([SAMPLE_LOG])
    scanner_alerts = [a for a in alerts if a.rule == "scanner-detected"]
    assert len(scanner_alerts) >= 1
    assert scanner_alerts[0].source_ip == "198.51.100.7"


def test_detect_sqli():
    alerts = detect_from_logs([SAMPLE_LOG])
    sqli_alerts = [a for a in alerts if a.rule == "sqli-attempt"]
    assert len(sqli_alerts) >= 1
    assert sqli_alerts[0].severity == "critical"


def test_detect_xss():
    alerts = detect_from_logs([XSS_LOG])
    xss_alerts = [a for a in alerts if a.rule == "xss-attempt"]
    assert len(xss_alerts) >= 1


def test_detect_traversal():
    alerts = detect_from_logs([TRAVERSAL_LOG])
    trav_alerts = [a for a in alerts if a.rule == "path-traversal"]
    assert len(trav_alerts) >= 1


def test_detect_brute_force():
    lines = [BRUTE_LOG_TEMPLATE.format(sec=i) for i in range(15)]
    alerts = detect_from_logs(lines)
    brute_alerts = [a for a in alerts if a.rule == "brute-force"]
    assert len(brute_alerts) == 1
    assert brute_alerts[0].severity == "critical"


def test_no_alerts_on_clean_log():
    alerts = detect_from_logs([CLEAN_LOG])
    assert len(alerts) == 0


def test_extract_iocs():
    alerts_data = [
        {"rule": "sqli-attempt", "severity": "critical",
         "source_ip": "198.51.100.7",
         "detail": "SQL injection pattern", "evidence": []},
    ]
    iocs = extract_iocs(alerts_data)
    ip_iocs = [i for i in iocs if i.type == "ip"]
    assert len(ip_iocs) == 1
    assert ip_iocs[0].value == "198.51.100.7"


def test_generate_firewall_rules():
    iocs = [
        IOC(type="ip", value="198.51.100.7", severity="critical",
            context="SQL injection"),
        IOC(type="ip", value="10.0.0.5", severity="low",
            context="Low risk"),
    ]
    rules = generate_firewall_rules(iocs)
    assert len(rules) == 1
    assert rules[0].source == "198.51.100.7"
    assert rules[0].action == "DROP"


def test_firewall_to_iptables():
    from responder import FirewallRule
    rules = [FirewallRule(
        action="DROP", direction="INPUT", protocol="all",
        source="198.51.100.7", comment="Block attacker",
    )]
    output = firewall_to_iptables(rules)
    assert "iptables" in output
    assert "198.51.100.7" in output
    assert "DROP" in output


def test_generate_yara_from_sqli():
    alerts_data = [
        {"rule": "sqli-attempt", "severity": "critical",
         "source_ip": "198.51.100.7",
         "detail": "SQL injection",
         "evidence": ["GET /products?id=1 UNION SELECT username FROM users"]},
    ]
    rules = generate_yara_rules(alerts_data)
    assert len(rules) >= 1
    assert rules[0].name == "detect_sqli_patterns"


def test_yara_to_text():
    from responder import YaraRule
    rule = YaraRule(
        name="test_rule",
        description="Test",
        strings=[("$s1", "UNION SELECT")],
        condition="any of them",
    )
    text = yara_to_text([rule])
    assert "rule test_rule" in text
    assert "UNION SELECT" in text


def test_build_timeline():
    alerts_data = [
        {"rule": "sqli-attempt", "severity": "critical",
         "source_ip": "198.51.100.7", "detail": "SQLi",
         "timestamp": "27/Oct/2026:23:41:08 +0000"},
        {"rule": "scanner-detected", "severity": "high",
         "source_ip": "198.51.100.7", "detail": "Nikto",
         "timestamp": "27/Oct/2026:23:38:00 +0000"},
    ]
    timeline = build_timeline(alerts_data)
    assert len(timeline) == 2
    assert timeline[0].timestamp < timeline[1].timestamp


def test_generate_recommendations():
    alerts_data = [
        {"rule": "brute-force", "severity": "critical", "source_ip": "1.2.3.4"},
        {"rule": "sqli-attempt", "severity": "critical", "source_ip": "1.2.3.4"},
    ]
    recs = generate_recommendations(alerts_data)
    assert len(recs) >= 3
    assert any("rate limit" in r.lower() for r in recs)
    assert any("parameteris" in r.lower() or "parameteriz" in r.lower() for r in recs)


def test_full_response_package():
    lines = [SAMPLE_LOG, XSS_LOG, TRAVERSAL_LOG]
    lines += [BRUTE_LOG_TEMPLATE.format(sec=i) for i in range(15)]
    alerts = detect_from_logs(lines)
    alert_dicts = [
        {"rule": a.rule, "severity": a.severity, "source_ip": a.source_ip,
         "detail": a.detail, "evidence": a.evidence, "timestamp": a.timestamp}
        for a in alerts
    ]
    pkg = build_response(alert_dicts)
    assert pkg.summary["total_alerts"] > 0
    assert len(pkg.iocs) > 0
    assert len(pkg.firewall_rules) > 0
    assert len(pkg.recommendations) > 0


def test_to_markdown():
    alerts_data = [
        {"rule": "sqli-attempt", "severity": "critical",
         "source_ip": "198.51.100.7", "detail": "SQLi",
         "evidence": ["GET /id=1 UNION SELECT"], "timestamp": "2026-10-27"},
    ]
    pkg = build_response(alerts_data)
    md = to_markdown(pkg)
    assert "# Incident response report" in md
    assert "198.51.100.7" in md
    assert "iptables" in md


def test_version_string():
    assert VERSION
    parts = VERSION.split(".")
    assert len(parts) == 3


def test_severity_score_empty():
    result = severity_score([])
    assert result["score"] == 0
    assert result["grade"] == "A"


def test_severity_score_critical():
    alerts = [
        {"severity": "critical"}, {"severity": "critical"}, {"severity": "high"},
    ]
    result = severity_score(alerts)
    assert result["score"] >= 80
    assert result["grade"] == "Critical"


def test_severity_score_low():
    alerts = [{"severity": "low"}]
    result = severity_score(alerts)
    assert result["score"] <= 10
    assert result["grade"] == "Low"


def test_severity_score_caps_at_100():
    alerts = [{"severity": "critical"}] * 10
    result = severity_score(alerts)
    assert result["score"] == 100


def test_to_stix_structure():
    alerts_data = [
        {"rule": "sqli-attempt", "severity": "critical",
         "source_ip": "198.51.100.7", "detail": "SQLi",
         "evidence": ["GET /id=1 UNION SELECT"], "timestamp": "2026-10-27"},
    ]
    pkg = build_response(alerts_data)
    stix = to_stix(pkg)
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) >= 2
    types = {o["type"] for o in stix["objects"]}
    assert "identity" in types
    assert "indicator" in types


def test_to_stix_ip_indicator():
    alerts_data = [
        {"rule": "scanner-detected", "severity": "high",
         "source_ip": "198.51.100.7",
         "detail": "Scanner user-agent: Nikto/2.1.6",
         "evidence": [], "timestamp": "2026-10-27"},
    ]
    pkg = build_response(alerts_data)
    stix = to_stix(pkg)
    indicators = [o for o in stix["objects"] if o["type"] == "indicator"]
    assert any("198.51.100.7" in i.get("pattern", "") for i in indicators)


def test_to_stix_empty_package():
    pkg = build_response([])
    stix = to_stix(pkg)
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) == 1  # just the identity


def test_detect_multiple_attack_types():
    lines = [SAMPLE_LOG, XSS_LOG, TRAVERSAL_LOG]
    alerts = detect_from_logs(lines)
    rules = {a.rule for a in alerts}
    assert "sqli-attempt" in rules
    assert "xss-attempt" in rules
    assert "path-traversal" in rules


def test_extract_iocs_dedup():
    alerts_data = [
        {"rule": "sqli-attempt", "severity": "critical",
         "source_ip": "198.51.100.7", "detail": "SQLi", "evidence": []},
        {"rule": "xss-attempt", "severity": "high",
         "source_ip": "198.51.100.7", "detail": "XSS", "evidence": []},
    ]
    iocs = extract_iocs(alerts_data)
    ip_iocs = [i for i in iocs if i.type == "ip"]
    assert len(ip_iocs) == 1
