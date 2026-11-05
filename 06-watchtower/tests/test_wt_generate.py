import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ipaddress
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timezone

from tools.generate_logs import generate

COMBINED = re.compile(
    r'^(\S+) \S+ \S+ \[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} \+0000)\] '
    r'"([A-Z]+) (\S+) HTTP/1\.[01]" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"$'
)
NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def parse_ts(text):
    return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")


def test_deterministic_same_seed():
    assert generate(7, 2) == generate(7, 2)


def test_different_seed_differs():
    assert generate(7, 2)[0] != generate(8, 2)[0]


def test_every_line_matches_combined_format():
    lines, _ = generate(3, 2)
    assert lines
    for ln in lines:
        assert COMBINED.match(ln), ln


def test_timestamps_sorted_and_start_default():
    lines, _ = generate(3, 2)
    times = [parse_ts(COMBINED.match(ln).group(2)) for ln in lines]
    assert times == sorted(times)
    assert times[0] >= datetime(2026, 11, 1, tzinfo=timezone.utc)


def test_label_ips_appear_in_log():
    lines, labels = generate(5, 3)
    seen = {ln.split()[0] for ln in lines}
    for row in labels:
        assert row["client_ip"] in seen, row


def test_all_ips_rfc5737():
    lines, labels = generate(5, 3)
    ips = {ln.split()[0] for ln in lines} | {r["client_ip"] for r in labels}
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        assert any(addr in n for n in NETS), ip


def test_every_scenario_present():
    _, labels = generate(7, 6)
    scenarios = {r["scenario"] for r in labels}
    for s in ("benign_browsing", "search_crawler", "health_check", "scanner", "enumeration",
              "bruteforce", "sqli", "log4shell", "traversal", "noisy_benign"):
        assert s in scenarios
    assert {r["label"] for r in labels} == {"benign", "malicious"}


def test_malicious_scenarios_have_one_ip_each_and_signatures():
    lines, labels = generate(7, 3)
    by_ip = defaultdict(list)
    for ln in lines:
        by_ip[ln.split()[0]].append(ln)
    ip = {r["scenario"]: r["client_ip"] for r in labels}
    assert any("Nikto" in x for x in by_ip[ip["scanner"]])
    assert any("sqlmap" in x for x in by_ip[ip["sqli"]])
    assert any("${jndi:" in x for x in by_ip[ip["log4shell"]])
    assert any("etc/passwd" in x or "etc%2fpasswd" in x for x in by_ip[ip["traversal"]])
    assert sum('"POST /login' in x and " 401 " in x for x in by_ip[ip["bruteforce"]]) >= 30
    assert any('"POST /login' in x and " 302 " in x for x in by_ip[ip["bruteforce"]])
    assert len(set(r["client_ip"] for r in labels)) == len(labels)


def test_noisy_benign_stays_under_enumeration_threshold():
    lines, labels = generate(7, 6)
    ip = next(r["client_ip"] for r in labels if r["scenario"] == "noisy_benign")
    times = []
    for ln in lines:
        m = COMBINED.match(ln)
        if m.group(1) == ip and m.group(5) == "404":
            times.append(parse_ts(m.group(2)).timestamp())
    assert 5 <= len(times) <= 12
    for i, t in enumerate(times):
        assert sum(1 for u in times[i:] if u - t < 60) < 20


def test_benign_dominates():
    lines, labels = generate(7, 6)
    mal = {r["client_ip"] for r in labels if r["label"] == "malicious"}
    frac = sum(ln.split()[0] in mal for ln in lines) / len(lines)
    assert 0.05 < frac < 0.2


def test_cli_writes_files(tmp_path):
    root = Path(__file__).resolve().parents[1]
    out, lab = tmp_path / "a.log", tmp_path / "l.csv"
    subprocess.run([sys.executable, str(root / "tools" / "generate_logs.py"), "--out", str(out),
                    "--labels", str(lab), "--seed", "1", "--hours", "1"], check=True)
    assert lab.read_text().startswith("client_ip,label,scenario")
    assert out.read_text().splitlines() == generate(1, 1)[0]


HARD = ("stealth_enum", "wp_bruteforce", "bruteforce_slow_success", "sqli_evasive", "traversal_encoded",
        "lookalike_searcher", "admin_user", "downloader", "office_nat")


def test_hard_profile_scenarios_labelled_and_present():
    lines, labels = generate(7, 6, profile="hard")
    by_s = {r["scenario"]: r for r in labels}
    seen = {ln.split()[0] for ln in lines}
    for s in HARD:
        assert s in by_s and by_s[s]["client_ip"] in seen
    assert by_s["stealth_enum"]["label"] == "malicious"
    assert by_s["office_nat"]["label"] == "benign"
    assert len(generate(7, 6)[1]) < len(labels)


def test_hard_profile_valid_deterministic_rfc5737():
    a = generate(7, 6, profile="hard")
    assert a == generate(7, 6, profile="hard")
    for ln in a[0]:
        assert COMBINED.match(ln), ln
        assert any(ipaddress.ip_address(ln.split()[0]) in n for n in NETS)
    times = [parse_ts(COMBINED.match(ln).group(2)) for ln in a[0]]
    assert times == sorted(times)


def test_hard_scenario_shapes():
    lines, labels = generate(7, 6, profile="hard")
    ip = {r["scenario"]: r["client_ip"] for r in labels}
    mine = lambda s: [ln for ln in lines if ln.startswith(ip[s] + " ")]
    assert len(mine("stealth_enum")) == 150
    assert sum("POST /wp-login.php" in x for x in mine("wp_bruteforce")) == 60
    assert sum(" 403 " in x and "/admin/products/save" in x for x in mine("admin_user")) == 12
    assert any("%25252e%25252e%25252f" in x for x in mine("traversal_encoded"))


def test_many_hours_no_ip_overflow_or_collision():
    for profile in ("easy", "hard"):
        lines, labels = generate(7, 100, profile=profile)
        ips = [r["client_ip"] for r in labels]
        assert len(ips) == len(set(ips))
        for ip in {ln.split()[0] for ln in lines} | set(ips):
            addr = ipaddress.ip_address(ip)
            assert any(addr in n for n in NETS), ip
        mal = {r["client_ip"] for r in labels if r["label"] == "malicious"}
        benign_scen = {r["client_ip"] for r in labels if r["label"] == "benign"}
        assert not mal & benign_scen
