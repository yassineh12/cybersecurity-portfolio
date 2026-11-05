from enricher import (
    is_bogon,
    is_private,
    guess_registry,
    score_ioc,
    enrich_ioc,
    enrich_all,
    map_to_mitre,
    to_markdown,
)


def test_bogon_detection():
    assert is_bogon("192.168.1.1")
    assert is_bogon("10.0.0.1")
    assert is_bogon("127.0.0.1")
    assert is_bogon("198.51.100.7")
    assert is_bogon("203.0.113.42")
    assert not is_bogon("8.8.8.8")


def test_private_detection():
    assert is_private("192.168.1.1")
    assert is_private("10.0.0.1")
    assert not is_private("8.8.8.8")


def test_invalid_ip():
    assert not is_bogon("not-an-ip")
    assert not is_private("not-an-ip")
    assert guess_registry("not-an-ip") == "unknown"


def test_guess_registry():
    assert guess_registry("8.8.8.8") == "ARIN"
    assert guess_registry("1.1.1.1") == "APNIC"
    assert guess_registry("5.5.5.5") == "RIPE"


def test_score_scanner_ua():
    rep = score_ioc("user_agent", "Nikto/2.1.6", "scanner detected")
    assert rep.score >= 40
    assert rep.category == "scanner"
    assert rep.confidence in ("medium", "high")


def test_score_sqli_payload():
    rep = score_ioc("payload", "UNION SELECT username FROM users", "SQL injection")
    assert rep.score >= 50
    assert rep.category == "injector"


def test_score_xss_payload():
    rep = score_ioc("payload", "<script>alert(1)</script>", "XSS attempt")
    assert rep.score >= 40
    assert rep.category == "injector"


def test_score_brute_force():
    rep = score_ioc("ip", "203.0.113.42", "brute-force: 87 failed login attempts")
    assert rep.score >= 50
    assert rep.category == "bruteforcer"


def test_score_clean_ip():
    rep = score_ioc("ip", "8.8.8.8", "normal traffic")
    assert rep.score < 30
    assert rep.confidence == "low"


def test_score_bogon_ip():
    rep = score_ioc("ip", "192.168.1.1", "internal scan")
    assert rep.score >= 20
    assert any("private" in r.lower() or "bogon" in r.lower() for r in rep.reasons)


def test_enrich_ip():
    raw = {"type": "ip", "value": "198.51.100.7", "severity": "critical",
           "context": "SQL injection source"}
    enriched = enrich_ioc(raw)
    assert enriched.type == "ip"
    assert "bogon" in enriched.tags
    assert enriched.reputation is not None
    assert enriched.geo is not None


def test_enrich_payload():
    raw = {"type": "payload", "value": "UNION SELECT", "severity": "critical",
           "context": "Attack pattern from 198.51.100.7"}
    enriched = enrich_ioc(raw)
    assert "sqli" in enriched.tags
    assert enriched.reputation.score >= 50


def test_enrich_user_agent():
    raw = {"type": "user_agent", "value": "sqlmap/1.5", "severity": "high",
           "context": "Known scanner tool"}
    enriched = enrich_ioc(raw)
    assert "tool-signature" in enriched.tags
    assert enriched.reputation.category == "scanner"


def test_related_iocs_linked():
    iocs = [
        {"type": "ip", "value": "198.51.100.7", "severity": "critical",
         "context": "SQL injection"},
        {"type": "payload", "value": "UNION SELECT", "severity": "critical",
         "context": "Attack pattern from 198.51.100.7"},
    ]
    report = enrich_all(iocs)
    payload_ioc = [e for e in report.iocs if e.type == "payload"][0]
    assert "198.51.100.7" in payload_ioc.related_iocs


def test_mitre_mapping_scanner():
    mappings = map_to_mitre({"scanner"})
    assert len(mappings) >= 1
    techniques = [m["technique"] for m in mappings]
    assert "T1595" in techniques


def test_mitre_mapping_bruteforcer():
    mappings = map_to_mitre({"bruteforcer"})
    assert len(mappings) >= 1
    techniques = [m["technique"] for m in mappings]
    assert "T1110" in techniques


def test_mitre_mapping_injector():
    mappings = map_to_mitre({"injector"})
    techniques = [m["technique"] for m in mappings]
    assert "T1190" in techniques


def test_mitre_mapping_unknown():
    mappings = map_to_mitre({"unknown"})
    assert mappings == []


def test_full_report():
    iocs = [
        {"type": "ip", "value": "198.51.100.7", "severity": "critical",
         "context": "Triggered sqli-attempt"},
        {"type": "user_agent", "value": "Nikto/2.1.6", "severity": "high",
         "context": "Known scanner tool"},
        {"type": "payload", "value": "UNION SELECT", "severity": "critical",
         "context": "From 198.51.100.7"},
    ]
    report = enrich_all(iocs)
    assert report.total_iocs == 3
    assert report.enriched_count == 3
    assert len(report.iocs) == 3
    assert len(report.mitre_mappings) >= 2
    assert report.attack_summary["high_risk_count"] >= 1


def test_to_markdown():
    iocs = [
        {"type": "ip", "value": "198.51.100.7", "severity": "critical",
         "context": "SQL injection source"},
    ]
    report = enrich_all(iocs)
    md = to_markdown(report)
    assert "# Threat intelligence report" in md
    assert "198.51.100.7" in md
    assert "Reputation score" in md


def test_empty_iocs():
    report = enrich_all([])
    assert report.total_iocs == 0
    assert report.enriched_count == 0
    assert report.iocs == []
