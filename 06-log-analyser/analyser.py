"""Web log analyser that detects scanners and attacks.

Parses Apache/nginx combined-format access logs, identifies suspicious
behaviour (scanning, brute-force, injection attempts, path traversal),
and produces an incident report with source IPs, timelines and evidence.

The purple-team payoff: attack your own lab with project 3, then feed the
logs into this analyser and watch it catch you.

Usage:
    python analyser.py access.log --out incident-report
    python analyser.py access.log --top 20

Only analyse logs from systems you own or are authorised to investigate.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Iterator


@dataclass
class LogEntry:
    ip: str
    timestamp: str
    method: str
    path: str
    status: int
    size: int
    referer: str
    user_agent: str
    raw: str


@dataclass
class Alert:
    rule_id: str
    severity: str
    title: str
    detail: str
    source_ip: str
    sample_paths: list[str] = field(default_factory=list)
    count: int = 0


@dataclass
class AnalysisResult:
    log_file: str
    total_lines: int = 0
    parsed_lines: int = 0
    unique_ips: int = 0
    alerts: list[Alert] = field(default_factory=list)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    status_distribution: dict[str, int] = field(default_factory=dict)
    scanner_user_agents: list[str] = field(default_factory=list)


# Combined log format regex
LOG_PATTERN = re.compile(
    r'(\S+)\s+'            # IP
    r'\S+\s+'              # ident
    r'\S+\s+'              # user
    r'\[([^\]]+)\]\s+'     # timestamp
    r'"(\S+)\s+(\S+)\s+[^"]*"\s+'  # method, path
    r'(\d+)\s+'            # status
    r'(\d+|-)\s*'          # size
    r'"([^"]*)"\s*'        # referer
    r'"([^"]*)"'           # user agent
)

SCANNER_AGENTS = [
    re.compile(r"nikto", re.I),
    re.compile(r"nmap", re.I),
    re.compile(r"sqlmap", re.I),
    re.compile(r"wpscan", re.I),
    re.compile(r"dirbuster", re.I),
    re.compile(r"gobuster", re.I),
    re.compile(r"masscan", re.I),
    re.compile(r"nuclei", re.I),
    re.compile(r"burp\s*suite", re.I),
    re.compile(r"zap", re.I),
    re.compile(r"acunetix", re.I),
    re.compile(r"nessus", re.I),
    re.compile(r"openvas", re.I),
    re.compile(r"crawl|spider|bot", re.I),
]

SQLI_PATTERNS = [
    re.compile(r"(?:union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s|;\s*delete\s)", re.I),
    re.compile(r"(?:select\s.*from\s|insert\s+into|update\s.*set\s)", re.I),
    re.compile(r"(?:benchmark\s*\(|sleep\s*\(|waitfor\s+delay)", re.I),
]

XSS_PATTERNS = [
    re.compile(r"<script", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"on(?:error|load|click|mouseover)\s*=", re.I),
    re.compile(r"alert\s*\(", re.I),
]

TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"/etc/(?:passwd|shadow|hosts)"),
    re.compile(r"/proc/self"),
    re.compile(r"(?:c:|d:)\\", re.I),
]

SENSITIVE_PATHS = [
    re.compile(r"/\.env"),
    re.compile(r"/\.git"),
    re.compile(r"/wp-admin"),
    re.compile(r"/wp-login\.php"),
    re.compile(r"/phpmyadmin", re.I),
    re.compile(r"/admin"),
    re.compile(r"/\.htaccess"),
    re.compile(r"/server-status"),
    re.compile(r"/actuator"),
    re.compile(r"/debug"),
    re.compile(r"/phpinfo"),
    re.compile(r"/config\b"),
    re.compile(r"/backup"),
    re.compile(r"/shell"),
    re.compile(r"/cmd"),
]


def parse_line(line: str) -> LogEntry | None:
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    return LogEntry(
        ip=m.group(1),
        timestamp=m.group(2),
        method=m.group(3),
        path=m.group(4),
        status=int(m.group(5)),
        size=int(m.group(6)) if m.group(6) != "-" else 0,
        referer=m.group(7),
        user_agent=m.group(8),
        raw=line.strip(),
    )


def parse_log(filepath: str) -> Iterator[LogEntry]:
    with open(filepath) as fh:
        for line in fh:
            entry = parse_line(line)
            if entry:
                yield entry


def detect_scanner_agents(entries_by_ip: dict[str, list[LogEntry]]) -> list[Alert]:
    alerts = []
    for ip, entries in entries_by_ip.items():
        agents = {e.user_agent for e in entries}
        for agent in agents:
            for pattern in SCANNER_AGENTS:
                if pattern.search(agent):
                    alerts.append(Alert(
                        rule_id="scanner-agent",
                        severity="high",
                        title=f"Known scanner user-agent from {ip}",
                        detail=f"User-Agent: {agent}",
                        source_ip=ip,
                        sample_paths=[e.path for e in entries[:5]],
                        count=len(entries),
                    ))
                    break
    return alerts


def detect_brute_force(entries_by_ip: dict[str, list[LogEntry]],
                       threshold: int = 10) -> list[Alert]:
    alerts = []
    login_paths = ("/login", "/wp-login", "/admin", "/signin", "/auth", "/api/login")
    for ip, entries in entries_by_ip.items():
        login_attempts = [e for e in entries
                          if any(lp in e.path.lower() for lp in login_paths)
                          and e.method == "POST"]
        failed = [e for e in login_attempts if e.status in (401, 403)]
        if len(failed) >= threshold:
            alerts.append(Alert(
                rule_id="brute-force",
                severity="critical",
                title=f"Possible brute-force from {ip} ({len(failed)} failed logins)",
                detail=f"{len(failed)} failed POST requests to login endpoints",
                source_ip=ip,
                sample_paths=list({e.path for e in failed})[:5],
                count=len(failed),
            ))
    return alerts


def detect_sqli(entries_by_ip: dict[str, list[LogEntry]]) -> list[Alert]:
    alerts = []
    for ip, entries in entries_by_ip.items():
        sqli_hits = []
        for e in entries:
            decoded = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), e.path)
            if any(p.search(decoded) for p in SQLI_PATTERNS):
                sqli_hits.append(e)
        if sqli_hits:
            alerts.append(Alert(
                rule_id="sqli-attempt",
                severity="critical",
                title=f"SQL injection attempt from {ip}",
                detail=f"{len(sqli_hits)} requests with SQL injection patterns",
                source_ip=ip,
                sample_paths=[e.path for e in sqli_hits[:5]],
                count=len(sqli_hits),
            ))
    return alerts


def detect_xss(entries_by_ip: dict[str, list[LogEntry]]) -> list[Alert]:
    alerts = []
    for ip, entries in entries_by_ip.items():
        xss_hits = []
        for e in entries:
            decoded = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), e.path)
            if any(p.search(decoded) for p in XSS_PATTERNS):
                xss_hits.append(e)
        if xss_hits:
            alerts.append(Alert(
                rule_id="xss-attempt",
                severity="high",
                title=f"XSS attempt from {ip}",
                detail=f"{len(xss_hits)} requests with XSS patterns",
                source_ip=ip,
                sample_paths=[e.path for e in xss_hits[:5]],
                count=len(xss_hits),
            ))
    return alerts


def detect_traversal(entries_by_ip: dict[str, list[LogEntry]]) -> list[Alert]:
    alerts = []
    for ip, entries in entries_by_ip.items():
        hits = [e for e in entries if any(p.search(e.path) for p in TRAVERSAL_PATTERNS)]
        if hits:
            alerts.append(Alert(
                rule_id="path-traversal",
                severity="high",
                title=f"Path traversal attempt from {ip}",
                detail=f"{len(hits)} requests with directory traversal patterns",
                source_ip=ip,
                sample_paths=[e.path for e in hits[:5]],
                count=len(hits),
            ))
    return alerts


def detect_sensitive_probing(entries_by_ip: dict[str, list[LogEntry]],
                              threshold: int = 3) -> list[Alert]:
    alerts = []
    for ip, entries in entries_by_ip.items():
        probes = set()
        probe_entries = []
        for e in entries:
            for pattern in SENSITIVE_PATHS:
                if pattern.search(e.path):
                    probes.add(e.path)
                    probe_entries.append(e)
                    break
        if len(probes) >= threshold:
            alerts.append(Alert(
                rule_id="sensitive-probing",
                severity="medium",
                title=f"Sensitive path probing from {ip} ({len(probes)} unique paths)",
                detail=f"Probed: {', '.join(sorted(probes)[:8])}",
                source_ip=ip,
                sample_paths=sorted(probes)[:5],
                count=len(probe_entries),
            ))
    return alerts


def detect_high_error_rate(entries_by_ip: dict[str, list[LogEntry]],
                            threshold: int = 50) -> list[Alert]:
    alerts = []
    for ip, entries in entries_by_ip.items():
        errors_404 = [e for e in entries if e.status == 404]
        if len(errors_404) >= threshold:
            alerts.append(Alert(
                rule_id="directory-scan",
                severity="medium",
                title=f"Possible directory scan from {ip} ({len(errors_404)} 404s)",
                detail=f"{len(errors_404)} requests returned 404 out of {len(entries)} total",
                source_ip=ip,
                sample_paths=[e.path for e in errors_404[:5]],
                count=len(errors_404),
            ))
    return alerts


def analyse(filepath: str, top_n: int = 10) -> AnalysisResult:
    result = AnalysisResult(log_file=filepath)
    entries_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
    ip_counter = Counter()
    path_counter = Counter()
    status_counter = Counter()
    all_agents = set()

    print(f"[1/2] Parsing {filepath} ...")
    total = 0
    with open(filepath) as fh:
        for line in fh:
            total += 1
            entry = parse_line(line)
            if entry:
                entries_by_ip[entry.ip].append(entry)
                ip_counter[entry.ip] += 1
                path_counter[entry.path] += 1
                status_counter[entry.status] += 1
                all_agents.add(entry.user_agent)

    result.total_lines = total
    result.parsed_lines = sum(ip_counter.values())
    result.unique_ips = len(entries_by_ip)
    result.top_ips = ip_counter.most_common(top_n)
    result.top_paths = path_counter.most_common(top_n)
    result.status_distribution = {str(k): v for k, v in status_counter.most_common()}

    result.scanner_user_agents = [
        ua for ua in all_agents
        if any(p.search(ua) for p in SCANNER_AGENTS)
    ]

    print(f"  {result.parsed_lines} entries from {result.unique_ips} unique IPs")

    print("[2/2] Running detection rules ...")
    result.alerts += detect_scanner_agents(entries_by_ip)
    result.alerts += detect_brute_force(entries_by_ip)
    result.alerts += detect_sqli(entries_by_ip)
    result.alerts += detect_xss(entries_by_ip)
    result.alerts += detect_traversal(entries_by_ip)
    result.alerts += detect_sensitive_probing(entries_by_ip)
    result.alerts += detect_high_error_rate(entries_by_ip)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result.alerts.sort(key=lambda a: (severity_order.get(a.severity, 9), -a.count))

    print(f"  {len(result.alerts)} alerts generated.")
    return result


def to_markdown(result: AnalysisResult) -> str:
    lines = [
        f"# Incident Report: {result.log_file}",
        "",
        f"**Total log entries:** {result.parsed_lines} (of {result.total_lines} lines)",
        f"**Unique source IPs:** {result.unique_ips}",
        f"**Alerts raised:** {len(result.alerts)}",
        "",
    ]

    if result.alerts:
        lines += ["## Alerts", "",
                   "| Severity | Type | Source IP | Count |",
                   "|---|---|---|---|"]
        for a in result.alerts:
            lines.append(f"| {a.severity.upper()} | {a.title[:50]} | {a.source_ip} | {a.count} |")

        lines += ["", "### Alert Details", ""]
        for a in result.alerts:
            lines.append(f"#### [{a.severity.upper()}] {a.title}")
            lines.append(f"- Rule: `{a.rule_id}`")
            lines.append(f"- Evidence: {a.detail}")
            if a.sample_paths:
                lines.append("- Sample paths:")
                for p in a.sample_paths:
                    lines.append(f"  - `{p}`")
            lines.append("")

    if result.top_ips:
        lines += ["## Top Source IPs", "",
                   "| IP | Requests |", "|---|---|"]
        for ip, count in result.top_ips:
            lines.append(f"| {ip} | {count} |")
        lines.append("")

    if result.status_distribution:
        lines += ["## HTTP Status Distribution", "",
                   "| Status | Count |", "|---|---|"]
        for status, count in sorted(result.status_distribution.items()):
            lines.append(f"| {status} | {count} |")
        lines.append("")

    if result.scanner_user_agents:
        lines += ["## Detected Scanner User-Agents", ""]
        for ua in result.scanner_user_agents:
            lines.append(f"- `{ua}`")
        lines.append("")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", help="path to access.log (combined format)")
    ap.add_argument("--out", default="incident-report")
    ap.add_argument("--top", type=int, default=10, help="top-N for IPs and paths")
    args = ap.parse_args()

    result = analyse(args.logfile, top_n=args.top)

    md = to_markdown(result)
    with open(f"{args.out}.md", "w") as fh:
        fh.write(md)
    with open(f"{args.out}.json", "w") as fh:
        json.dump(asdict(result), fh, indent=2, default=str)

    print(f"\nReport: {args.out}.md / {args.out}.json")


if __name__ == "__main__":
    main()
