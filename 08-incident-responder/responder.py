"""Incident response toolkit.

Takes alerts from project 6's log analyser (or raw log files) and
generates actionable response artifacts: firewall rules, IOC lists,
YARA rules for detected patterns, and a chronological event timeline.

Usage:
    python responder.py alerts.json --out response-package
    python responder.py access.log --parse-first --out response-package

The second form runs project 6's analyser internally, then responds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    """Indicator of compromise."""
    type: str  # ip, url_pattern, user_agent, payload
    value: str
    severity: str
    context: str
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class FirewallRule:
    """A single firewall rule."""
    action: str  # DROP, REJECT
    direction: str  # INPUT, OUTPUT
    protocol: str  # tcp, udp, all
    source: str
    destination: str = "any"
    port: str = ""
    comment: str = ""


@dataclass
class TimelineEvent:
    """A single event on the incident timeline."""
    timestamp: str
    source_ip: str
    event_type: str
    detail: str
    severity: str


@dataclass
class YaraRule:
    """A YARA rule for detecting attack patterns in logs or traffic."""
    name: str
    description: str
    strings: list[tuple[str, str]] = field(default_factory=list)
    condition: str = "any of them"


@dataclass
class ResponsePackage:
    """The full incident response package."""
    generated_at: str
    summary: dict[str, Any] = field(default_factory=dict)
    iocs: list[IOC] = field(default_factory=list)
    firewall_rules: list[FirewallRule] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    yara_rules: list[YaraRule] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Log parsing (lightweight, for --parse-first mode)
# ---------------------------------------------------------------------------

LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+[^"]*"\s+'
    r'(?P<status>\d{3})\s+\d+\s+'
    r'"[^"]*"\s+"(?P<ua>[^"]*)"'
)

SCANNER_AGENTS = [
    "nikto", "nmap", "sqlmap", "wpscan", "dirbuster", "gobuster",
    "nuclei", "burp", "zap", "acunetix", "nessus", "masscan",
]

SQLI_PATTERNS = [
    r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s*'",
    r"sleep\s*\(", r"benchmark\s*\(", r";\s*drop\s+table",
    r"information_schema", r"load_file\s*\(",
]

XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
    r"onfocus\s*=", r"onmouseover\s*=", r"alert\s*\(",
]

TRAVERSAL_PATTERNS = [
    r"\.\./", r"/etc/passwd", r"/etc/shadow", r"/proc/self",
    r"\\\\", r"\.\.\\",
]

SENSITIVE_PATHS = [
    "/admin", "/.env", "/.git", "/wp-admin", "/phpmyadmin",
    "/server-status", "/wp-login", "/backup", "/.htaccess",
    "/config", "/debug", "/console",
]


@dataclass
class LogAlert:
    """Alert produced from raw log parsing."""
    rule: str
    severity: str
    source_ip: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    timestamp: str = ""


def parse_log_line(line: str) -> dict | None:
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    return m.groupdict()


def detect_from_logs(lines: list[str]) -> list[LogAlert]:
    """Run detection rules against raw log lines."""
    entries_by_ip: dict[str, list[dict]] = defaultdict(list)
    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            entries_by_ip[parsed["ip"]].append({**parsed, "raw": line.strip()})

    alerts: list[LogAlert] = []

    for ip, entries in entries_by_ip.items():
        ua_lower = entries[0]["ua"].lower() if entries else ""
        for agent in SCANNER_AGENTS:
            if agent in ua_lower:
                alerts.append(LogAlert(
                    rule="scanner-detected",
                    severity="high",
                    source_ip=ip,
                    detail=f"Scanner user-agent: {entries[0]['ua']}",
                    evidence=[e["raw"] for e in entries[:3]],
                    timestamp=entries[0]["ts"],
                ))
                break

        failed_posts = [
            e for e in entries
            if e["method"] == "POST"
            and e["status"].startswith("4")
            and ("login" in e["path"].lower() or "auth" in e["path"].lower())
        ]
        if len(failed_posts) >= 10:
            alerts.append(LogAlert(
                rule="brute-force",
                severity="critical",
                source_ip=ip,
                detail=f"{len(failed_posts)} failed login attempts",
                evidence=[e["raw"] for e in failed_posts[:5]],
                timestamp=failed_posts[0]["ts"],
            ))

        for entry in entries:
            decoded = unquote(entry["path"]).lower()
            for pat in SQLI_PATTERNS:
                if re.search(pat, decoded, re.IGNORECASE):
                    alerts.append(LogAlert(
                        rule="sqli-attempt",
                        severity="critical",
                        source_ip=ip,
                        detail=f"SQL injection pattern in {entry['path']}",
                        evidence=[entry["raw"]],
                        timestamp=entry["ts"],
                    ))
                    break

            for pat in XSS_PATTERNS:
                if re.search(pat, decoded, re.IGNORECASE):
                    alerts.append(LogAlert(
                        rule="xss-attempt",
                        severity="high",
                        source_ip=ip,
                        detail=f"XSS pattern in {entry['path']}",
                        evidence=[entry["raw"]],
                        timestamp=entry["ts"],
                    ))
                    break

            for pat in TRAVERSAL_PATTERNS:
                if re.search(pat, decoded, re.IGNORECASE):
                    alerts.append(LogAlert(
                        rule="path-traversal",
                        severity="high",
                        source_ip=ip,
                        detail=f"Path traversal pattern in {entry['path']}",
                        evidence=[entry["raw"]],
                        timestamp=entry["ts"],
                    ))
                    break

        sensitive_hits = [
            e for e in entries
            if any(s in e["path"].lower() for s in SENSITIVE_PATHS)
        ]
        if len(sensitive_hits) >= 3:
            alerts.append(LogAlert(
                rule="sensitive-probing",
                severity="medium",
                source_ip=ip,
                detail=f"{len(sensitive_hits)} requests to sensitive paths",
                evidence=[e["raw"] for e in sensitive_hits[:5]],
                timestamp=sensitive_hits[0]["ts"],
            ))

        status_404 = [e for e in entries if e["status"] == "404"]
        if len(status_404) >= 50:
            alerts.append(LogAlert(
                rule="directory-scan",
                severity="medium",
                source_ip=ip,
                detail=f"{len(status_404)} requests returned 404",
                evidence=[e["raw"] for e in status_404[:3]],
                timestamp=status_404[0]["ts"],
            ))

    return alerts


# ---------------------------------------------------------------------------
# Response generation
# ---------------------------------------------------------------------------

def extract_iocs(alerts: list[dict]) -> list[IOC]:
    """Extract indicators of compromise from alerts."""
    seen = set()
    iocs: list[IOC] = []

    for alert in alerts:
        ip = alert.get("source_ip", "")
        severity = alert.get("severity", "medium")
        rule = alert.get("rule", "")
        detail = alert.get("detail", "")

        if ip and ip not in seen:
            seen.add(ip)
            iocs.append(IOC(
                type="ip",
                value=ip,
                severity=severity,
                context=f"Triggered {rule}: {detail}",
            ))

        if "user-agent" in detail.lower() or "scanner" in rule.lower():
            ua_match = re.search(r"user-agent:\s*(.+)", detail, re.IGNORECASE)
            if ua_match:
                ua = ua_match.group(1).strip()
                key = f"ua:{ua}"
                if key not in seen:
                    seen.add(key)
                    iocs.append(IOC(
                        type="user_agent",
                        value=ua,
                        severity="high",
                        context="Known scanner tool",
                    ))

        evidence_list = alert.get("evidence", [])
        for ev in evidence_list:
            decoded = unquote(str(ev))
            for pat in SQLI_PATTERNS + XSS_PATTERNS:
                match = re.search(pat, decoded, re.IGNORECASE)
                if match:
                    payload = match.group(0)
                    key = f"payload:{payload[:60]}"
                    if key not in seen:
                        seen.add(key)
                        iocs.append(IOC(
                            type="payload",
                            value=payload,
                            severity=severity,
                            context=f"Attack pattern from {ip}",
                        ))

    return iocs


def generate_firewall_rules(iocs: list[IOC]) -> list[FirewallRule]:
    """Generate iptables-style firewall rules from IOCs."""
    rules: list[FirewallRule] = []
    blocked_ips = set()

    for ioc in iocs:
        if ioc.type == "ip" and ioc.severity in ("critical", "high"):
            if ioc.value not in blocked_ips:
                blocked_ips.add(ioc.value)
                rules.append(FirewallRule(
                    action="DROP",
                    direction="INPUT",
                    protocol="all",
                    source=ioc.value,
                    comment=f"Block {ioc.value}: {ioc.context[:60]}",
                ))

    return rules


def build_timeline(alerts: list[dict]) -> list[TimelineEvent]:
    """Build a chronological timeline from alerts."""
    events: list[TimelineEvent] = []

    for alert in alerts:
        ts = alert.get("timestamp", "")
        events.append(TimelineEvent(
            timestamp=ts,
            source_ip=alert.get("source_ip", "unknown"),
            event_type=alert.get("rule", "unknown"),
            detail=alert.get("detail", ""),
            severity=alert.get("severity", "medium"),
        ))

    events.sort(key=lambda e: e.timestamp)
    return events


def generate_yara_rules(alerts: list[dict]) -> list[YaraRule]:
    """Generate YARA rules for detected attack patterns."""
    rules: list[YaraRule] = []
    rule_types_seen = set()

    sqli_payloads = []
    xss_payloads = []
    traversal_payloads = []

    for alert in alerts:
        rule = alert.get("rule", "")
        for ev in alert.get("evidence", []):
            decoded = unquote(str(ev))
            if "sqli" in rule:
                for pat in SQLI_PATTERNS:
                    m = re.search(pat, decoded, re.IGNORECASE)
                    if m:
                        sqli_payloads.append(m.group(0))
            elif "xss" in rule:
                for pat in XSS_PATTERNS:
                    m = re.search(pat, decoded, re.IGNORECASE)
                    if m:
                        xss_payloads.append(m.group(0))
            elif "traversal" in rule:
                for pat in TRAVERSAL_PATTERNS:
                    m = re.search(pat, decoded, re.IGNORECASE)
                    if m:
                        traversal_payloads.append(m.group(0))

    if sqli_payloads and "sqli" not in rule_types_seen:
        rule_types_seen.add("sqli")
        strings = []
        seen_strs = set()
        for i, p in enumerate(sqli_payloads):
            normalized = p.strip().lower()
            if normalized not in seen_strs:
                seen_strs.add(normalized)
                strings.append((f"$sqli_{i}", p))
        rules.append(YaraRule(
            name="detect_sqli_patterns",
            description="SQL injection patterns observed in incident",
            strings=strings[:10],
            condition="any of them",
        ))

    if xss_payloads and "xss" not in rule_types_seen:
        rule_types_seen.add("xss")
        strings = []
        seen_strs = set()
        for i, p in enumerate(xss_payloads):
            normalized = p.strip().lower()
            if normalized not in seen_strs:
                seen_strs.add(normalized)
                strings.append((f"$xss_{i}", p))
        rules.append(YaraRule(
            name="detect_xss_patterns",
            description="XSS patterns observed in incident",
            strings=strings[:10],
            condition="any of them",
        ))

    if traversal_payloads and "traversal" not in rule_types_seen:
        rule_types_seen.add("traversal")
        strings = []
        seen_strs = set()
        for i, p in enumerate(traversal_payloads):
            normalized = p.strip().lower()
            if normalized not in seen_strs:
                seen_strs.add(normalized)
                strings.append((f"$trav_{i}", p))
        rules.append(YaraRule(
            name="detect_traversal_patterns",
            description="Path traversal patterns observed in incident",
            strings=strings[:10],
            condition="any of them",
        ))

    return rules


def generate_recommendations(alerts: list[dict]) -> list[str]:
    """Generate prioritised recommendations from alert types."""
    recs: list[str] = []
    rules_seen = {a.get("rule", "") for a in alerts}
    ips = {a.get("source_ip", "") for a in alerts if a.get("severity") in ("critical", "high")}

    if ips:
        recs.append(f"Block the following IPs at the firewall immediately: {', '.join(sorted(ips))}")

    if "brute-force" in rules_seen:
        recs.append("Implement rate limiting on authentication endpoints (max 5 attempts per minute per IP)")
        recs.append("Enable account lockout after 10 consecutive failed attempts")
        recs.append("Deploy MFA on all user-facing login pages")

    if "sqli-attempt" in rules_seen:
        recs.append("Audit all database queries for parameterised statements — replace string concatenation with bound parameters")
        recs.append("Deploy a WAF rule to block common SQL injection patterns")
        recs.append("Check database logs for successful data exfiltration during the attack window")

    if "xss-attempt" in rules_seen:
        recs.append("Implement output encoding on all user-controlled input rendered in HTML")
        recs.append("Add Content-Security-Policy header to restrict inline script execution")

    if "path-traversal" in rules_seen:
        recs.append("Validate file paths against an allowlist; reject any path containing '..'")
        recs.append("Run the application with minimal filesystem permissions")

    if "scanner-detected" in rules_seen:
        recs.append("Review the full request log from scanner IPs for any successful exploitation (HTTP 200 on sensitive endpoints)")

    if "sensitive-probing" in rules_seen:
        recs.append("Restrict access to administrative and configuration endpoints by IP allowlist or VPN")
        recs.append("Remove exposed .env, .git, and phpinfo files from the web root")

    return recs


# ---------------------------------------------------------------------------
# Build the full response package
# ---------------------------------------------------------------------------

def build_response(alerts: list[dict]) -> ResponsePackage:
    """Build a full incident response package from alerts."""
    severity_counts: dict[str, int] = defaultdict(int)
    rule_counts: dict[str, int] = defaultdict(int)
    unique_ips: set[str] = set()

    for a in alerts:
        severity_counts[a.get("severity", "unknown")] += 1
        rule_counts[a.get("rule", "unknown")] += 1
        unique_ips.add(a.get("source_ip", ""))

    iocs = extract_iocs(alerts)
    fw_rules = generate_firewall_rules(iocs)
    timeline = build_timeline(alerts)
    yara_rules = generate_yara_rules(alerts)
    recommendations = generate_recommendations(alerts)

    return ResponsePackage(
        generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        summary={
            "total_alerts": len(alerts),
            "severity_breakdown": dict(severity_counts),
            "rule_breakdown": dict(rule_counts),
            "unique_source_ips": len(unique_ips),
            "iocs_extracted": len(iocs),
            "firewall_rules_generated": len(fw_rules),
        },
        iocs=iocs,
        firewall_rules=fw_rules,
        timeline=timeline,
        yara_rules=yara_rules,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def firewall_to_iptables(rules: list[FirewallRule]) -> str:
    """Render firewall rules as iptables commands."""
    lines = ["#!/bin/bash", "# Auto-generated firewall rules — review before applying", ""]
    for r in rules:
        cmd = f"iptables -A {r.direction} -s {r.source}"
        if r.protocol != "all":
            cmd += f" -p {r.protocol}"
        if r.port:
            cmd += f" --dport {r.port}"
        cmd += f" -j {r.action}"
        if r.comment:
            cmd += f'  # {r.comment}'
        lines.append(cmd)
    return "\n".join(lines)


def yara_to_text(rules: list[YaraRule]) -> str:
    """Render YARA rules as .yar text."""
    blocks: list[str] = []
    for rule in rules:
        lines = [f"rule {rule.name} {{"]
        lines.append(f'    meta:')
        lines.append(f'        description = "{rule.description}"')
        lines.append(f'        generated = "auto"')
        lines.append(f'    strings:')
        for name, val in rule.strings:
            safe = val.replace('"', '\\"')
            lines.append(f'        {name} = "{safe}" nocase')
        lines.append(f'    condition:')
        lines.append(f'        {rule.condition}')
        lines.append("}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def to_markdown(pkg: ResponsePackage) -> str:
    """Render the full response package as a markdown report."""
    lines = ["# Incident response report", ""]
    lines.append(f"Generated: {pkg.generated_at}")
    lines.append("")

    s = pkg.summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total alerts:** {s.get('total_alerts', 0)}")
    lines.append(f"- **Unique source IPs:** {s.get('unique_source_ips', 0)}")
    lines.append(f"- **IOCs extracted:** {s.get('iocs_extracted', 0)}")
    lines.append(f"- **Firewall rules generated:** {s.get('firewall_rules_generated', 0)}")
    lines.append("")

    sev = s.get("severity_breakdown", {})
    if sev:
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for k in ["critical", "high", "medium", "low"]:
            if k in sev:
                lines.append(f"| {k.title()} | {sev[k]} |")
        lines.append("")

    if pkg.timeline:
        lines.append("## Timeline")
        lines.append("")
        lines.append("| Time | Source IP | Event | Severity | Detail |")
        lines.append("|---|---|---|---|---|")
        for ev in pkg.timeline:
            lines.append(f"| {ev.timestamp} | {ev.source_ip} | {ev.event_type} | {ev.severity} | {ev.detail} |")
        lines.append("")

    if pkg.iocs:
        lines.append("## Indicators of compromise")
        lines.append("")
        lines.append("| Type | Value | Severity | Context |")
        lines.append("|---|---|---|---|")
        for ioc in pkg.iocs:
            lines.append(f"| {ioc.type} | `{ioc.value}` | {ioc.severity} | {ioc.context} |")
        lines.append("")

    if pkg.firewall_rules:
        lines.append("## Firewall rules")
        lines.append("")
        lines.append("```bash")
        lines.append(firewall_to_iptables(pkg.firewall_rules))
        lines.append("```")
        lines.append("")

    if pkg.yara_rules:
        lines.append("## YARA rules")
        lines.append("")
        lines.append("```yara")
        lines.append(yara_to_text(pkg.yara_rules))
        lines.append("```")
        lines.append("")

    if pkg.recommendations:
        lines.append("## Recommendations")
        lines.append("")
        for i, rec in enumerate(pkg.recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Incident response toolkit")
    parser.add_argument("input", help="Alerts JSON file, or raw log file with --parse-first")
    parser.add_argument("--parse-first", action="store_true",
                        help="Input is a raw log file; run detection rules first")
    parser.add_argument("--out", default="response",
                        help="Output base name (writes .md and .json)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    if args.parse_first:
        raw_lines = input_path.read_text().splitlines()
        log_alerts = detect_from_logs(raw_lines)
        alerts = [asdict(a) for a in log_alerts]
    else:
        alerts = json.loads(input_path.read_text())
        if isinstance(alerts, dict):
            alerts = alerts.get("alerts", [])

    if not alerts:
        print("No alerts found in input.")
        sys.exit(0)

    pkg = build_response(alerts)

    md_path = Path(f"{args.out}.md")
    md_path.write_text(to_markdown(pkg))

    json_path = Path(f"{args.out}.json")
    json_data = {
        "generated_at": pkg.generated_at,
        "summary": pkg.summary,
        "iocs": [asdict(i) for i in pkg.iocs],
        "firewall_rules": [asdict(r) for r in pkg.firewall_rules],
        "timeline": [asdict(e) for e in pkg.timeline],
        "yara_rules": [{"name": y.name, "description": y.description,
                        "strings": y.strings, "condition": y.condition}
                       for y in pkg.yara_rules],
        "recommendations": pkg.recommendations,
    }
    json_path.write_text(json.dumps(json_data, indent=2))

    print(f"Response package written to {md_path} and {json_path}")
    print(f"  Alerts processed: {pkg.summary['total_alerts']}")
    print(f"  IOCs extracted: {pkg.summary['iocs_extracted']}")
    print(f"  Firewall rules: {pkg.summary['firewall_rules_generated']}")
    print(f"  Recommendations: {len(pkg.recommendations)}")


if __name__ == "__main__":
    main()
