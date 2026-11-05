import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datetime import datetime, timedelta, timezone

from watchtower.correlate import (
    correlate, exploit_succeeded, score_alerts, severity_for_score, stage_of, summarize,
)
from watchtower.models import Alert

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
IP = "203.0.113.5"
NIKTO_LINE = (f'{IP} - - [01/Mar/2026:12:00:00 +0000] "GET /admin.php HTTP/1.1" 404 0 '
              f'"-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)"')
SQLI_OK = f'{IP} - - [01/Mar/2026:12:05:00 +0000] "GET /item?id=1%27+OR+1=1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"'
SQLI_BAD = f'{IP} - - [01/Mar/2026:12:05:01 +0000] "GET /item?id=1%27+UNION+SELECT HTTP/1.1" 500 0 "-" "sqlmap/1.7"'

TECH = {"SIG-UA-SCANNER": "T1595.002", "SIG-SENSITIVE-PATH": "T1595.003", "BEH-404-BURST": "T1595.003",
        "SIG-SQLI": "T1190", "SIG-XSS": "T1190", "SIG-TRAVERSAL": "T1190", "SIG-CMDI": "T1190",
        "SIG-LOG4SHELL": "T1190", "BEH-BRUTE-FORCE": "T1110", "BEH-BRUTE-SUCCESS": "T1110",
        "BEH-RATE-SPIKE": "T1499"}


def alert(rule, severity, minute=0, ip=IP, count=1, evidence=(), detail="", technique=None):
    t = T0 + timedelta(minutes=minute)
    return Alert(rule_id=rule, title=rule.title(), severity=severity, client_ip=ip,
                 first_seen=t, last_seen=t + timedelta(seconds=30), event_count=count,
                 technique=technique or TECH.get(rule, ""), evidence=list(evidence), detail=detail)


def test_empty_input_gives_no_incidents():
    assert correlate([]) == []


def test_groups_alerts_per_client():
    incs = correlate([alert("SIG-UA-SCANNER", "medium"), alert("SIG-XSS", "medium", ip="198.51.100.7"),
                      alert("SIG-SQLI", "high", minute=3)])
    assert {i.client_ip for i in incs} == {IP, "198.51.100.7"}
    mine = next(i for i in incs if i.client_ip == IP)
    assert [a.rule_id for a in mine.alerts] == ["SIG-UA-SCANNER", "SIG-SQLI"]


def test_lone_alert_keeps_its_own_severity():
    for sev in ("low", "medium", "high", "critical"):
        rule = {"low": "BEH-RATE-SPIKE", "medium": "SIG-SENSITIVE-PATH",
                "high": "SIG-TRAVERSAL", "critical": "SIG-LOG4SHELL"}[sev]
        (inc,) = correlate([alert(rule, sev)])
        assert inc.severity == sev, (rule, inc.score)


def test_stage_mapping_covers_every_rule():
    assert stage_of(alert("SIG-UA-SCANNER", "medium")) == "recon"
    assert stage_of(alert("BEH-404-BURST", "medium")) == "recon"
    assert stage_of(alert("SIG-CMDI", "high")) == "exploit"
    assert stage_of(alert("BEH-BRUTE-SUCCESS", "critical")) == "credential-access"
    assert stage_of(alert("BEH-RATE-SPIKE", "low")) == "impact"
    # unknown rule falls back to its ATT&CK technique
    assert stage_of(alert("CUSTOM-THING", "low", technique="T1190")) == "exploit"
    assert stage_of(alert("CUSTOM-THING", "low", technique="T9999")) is None


def test_stages_listed_in_order_first_reached():
    (inc,) = correlate([alert("BEH-BRUTE-FORCE", "high", minute=10),
                        alert("SIG-UA-SCANNER", "medium", minute=0),
                        alert("SIG-SQLI", "high", minute=5),
                        alert("SIG-SENSITIVE-PATH", "medium", minute=6)])
    assert inc.stages == ["recon", "exploit", "credential-access"]
    assert inc.first_seen == T0
    assert inc.last_seen == T0 + timedelta(minutes=10, seconds=30)


def test_recon_then_exploit_scores_higher_than_exploit_alone():
    alone = score_alerts([alert("SIG-SQLI", "high")])
    chain = score_alerts([alert("SIG-UA-SCANNER", "medium"), alert("SIG-SQLI", "high", minute=5)])
    reversed_order = score_alerts([alert("SIG-SQLI", "high"), alert("SIG-UA-SCANNER", "medium", minute=5)])
    assert alone == 60
    assert chain == 60 + 5 + 10 + 10
    assert reversed_order == chain - 10          # no sequence bonus when exploit came first
    assert severity_for_score(chain) == "critical"


def test_exploit_success_detected_and_scored():
    plain = alert("SIG-SQLI", "high", evidence=[SQLI_BAD])
    won = alert("SIG-SQLI", "critical", evidence=[SQLI_OK, SQLI_BAD],
                detail="2 matching request(s). 1 request(s) were answered with HTTP 2xx.")
    assert not exploit_succeeded(plain)
    assert exploit_succeeded(won)
    assert score_alerts([won]) == 85             # already escalated: no second bonus
    # a 2xx on a recon alert is normal and must not count as exploit success
    assert not exploit_succeeded(alert("SIG-UA-SCANNER", "medium", evidence=[SQLI_OK]))


def test_success_signal_from_detail_or_evidence_alone():
    by_detail = alert("SIG-LOG4SHELL", "critical", detail="answered with HTTP 2xx")
    by_evidence = alert("SIG-TRAVERSAL", "high", evidence=[SQLI_OK])
    numbers_only = alert("SIG-SQLI", "high", detail="250 matching request(s)")
    assert exploit_succeeded(by_detail)
    assert exploit_succeeded(by_evidence)
    assert not exploit_succeeded(numbers_only)


def test_brute_force_success_is_critical():
    (inc,) = correlate([alert("BEH-BRUTE-FORCE", "high", count=40),
                        alert("BEH-BRUTE-SUCCESS", "critical", minute=4)])
    assert inc.severity == "critical"
    assert inc.score == 100                       # 85 + 5 + 15, clamped
    assert "brute-forced a login (40 failed attempts)" in inc.summary
    assert "ended in a successful login" in inc.summary


def test_score_is_clamped_to_0_100():
    many = [alert(r, "critical", minute=i) for i, r in enumerate(TECH)]
    assert score_alerts(many) == 100
    assert score_alerts([]) == 0


def test_incidents_sorted_by_score_desc_then_deterministic():
    incs = correlate([
        alert("BEH-RATE-SPIKE", "low", ip="192.0.2.50"),
        alert("SIG-LOG4SHELL", "critical", ip="198.51.100.9"),
        alert("SIG-SENSITIVE-PATH", "medium", ip="192.0.2.77", minute=2),
        alert("SIG-SENSITIVE-PATH", "medium", ip="192.0.2.66", minute=1),
    ])
    assert [i.client_ip for i in incs] == ["198.51.100.9", "192.0.2.66", "192.0.2.77", "192.0.2.50"]
    assert [i.score for i in incs] == sorted((i.score for i in incs), reverse=True)


def test_summary_matches_brief_example():
    scan = alert("SIG-UA-SCANNER", "medium", evidence=[NIKTO_LINE])
    sqli = alert("SIG-SQLI", "critical", minute=5, evidence=[SQLI_OK, SQLI_BAD],
                 detail="1 request(s) were answered with HTTP 2xx")
    (inc,) = correlate([sqli, scan])
    assert inc.summary == ("203.0.113.5 ran a nikto scan, then attempted SQL injection; "
                           "one attempt returned 200.")


def test_summary_three_steps_and_unknown_scanner():
    s = summarize(IP, [alert("SIG-UA-SCANNER", "medium", evidence=["no ua here"]),
                       alert("SIG-SENSITIVE-PATH", "medium", minute=1),
                       alert("SIG-TRAVERSAL", "high", minute=2)])
    assert s == (f"{IP} ran an automated scanner, probed for sensitive files, "
                 f"then attempted path traversal.")


def test_summary_names_scanner_from_user_agent_not_path():
    line = f'{IP} - - [01/Mar/2026:12:00:00 +0000] "GET /nikto HTTP/1.1" 404 0 "-" "Nmap Scripting Engine"'
    assert summarize(IP, [alert("SIG-UA-SCANNER", "medium", evidence=[line])]) == f"{IP} ran an nmap scan."


def test_summary_counts_and_unknown_rule():
    s = summarize(IP, [alert("BEH-404-BURST", "medium", count=37),
                       alert("BEH-RATE-SPIKE", "low", minute=1, count=1),
                       alert("X-NEW-RULE", "low", minute=2)])
    assert s.startswith(f"{IP} enumerated paths (37 requests answered 404), "
                        f"flooded the site with one request, then triggered ")
    assert s.endswith(".")


def test_scoring_weights_are_configurable():
    custom = {"severity_points": {"medium": 50}, "severity_cutoffs": {"high": 50}}
    (inc,) = correlate([alert("SIG-UA-SCANNER", "medium")], custom)
    assert inc.score == 50 and inc.severity == "high"


def test_incident_to_dict_roundtrip_shape():
    (inc,) = correlate([alert("SIG-XSS", "medium")])
    d = inc.to_dict()
    assert d["client_ip"] == IP and d["stages"] == ["exploit"] and len(d["alerts"]) == 1


def test_same_second_alerts_told_in_kill_chain_order():
    s = summarize(IP, [alert("SIG-SQLI", "high"), alert("SIG-UA-SCANNER", "medium", evidence=['"sqlmap/1.7"'])])
    assert s == f"{IP} ran a sqlmap scan, then attempted SQL injection."


def test_success_count_taken_from_detail_when_evidence_is_capped():
    a = alert("SIG-SQLI", "critical", evidence=[SQLI_OK] * 5,
              detail="40 matching request(s). 12 request(s) were answered with HTTP 2xx, so ...")
    assert summarize(IP, [a]).endswith("; 12 attempts returned 200.")


def test_2xx_answer_counted_once_lone_alert_keeps_its_severity():
    # signatures.py escalates SQLI high -> critical for a 2xx and says so in detail
    sqli_200 = alert("SIG-SQLI", "critical", evidence=[SQLI_OK],
                     detail="1 request(s) were answered with HTTP 2xx; severity raised to critical.")
    (inc,) = correlate([sqli_200])
    assert inc.score == 85 and inc.severity == "critical"
    # XSS medium -> high for a 2xx: still a lone high, not critical
    xss_200 = alert("SIG-XSS", "high", detail="answered with HTTP 2xx")
    assert score_alerts([xss_200]) == 60 and severity_for_score(60) == "high"
    # Log4Shell cannot be escalated past critical, so the bonus applies instead
    l4s_200 = alert("SIG-LOG4SHELL", "critical", detail="answered with HTTP 2xx")
    assert score_alerts([l4s_200]) == 100
    assert score_alerts([sqli_200]) < score_alerts([l4s_200])
