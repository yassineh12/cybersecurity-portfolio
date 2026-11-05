"""Threat intelligence enricher.

Takes IOCs (indicators of compromise) from project 8 or manual input
and enriches them with context from public sources: WHOIS, DNS,
geolocation, and reputation scoring based on observable behaviour.

Usage:
    python enricher.py iocs.json --out enriched-report
    python enricher.py --ip 198.51.100.7 --ip 203.0.113.42

Does not require API keys — uses only freely available public data.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DNSRecord:
    """A single DNS resolution result."""
    hostname: str
    record_type: str  # A, AAAA, CNAME, MX, PTR
    value: str


@dataclass
class GeoInfo:
    """IP geolocation derived from allocation data."""
    country_code: str = ""
    registry: str = ""  # ARIN, RIPE, APNIC, etc.
    allocation_date: str = ""


@dataclass
class ReputationScore:
    """Reputation assessment for an IOC."""
    score: int  # 0 (clean) to 100 (malicious)
    category: str  # scanner, bruteforcer, injector, unknown
    confidence: str  # high, medium, low
    reasons: list[str] = field(default_factory=list)


@dataclass
class EnrichedIOC:
    """An IOC enriched with threat intelligence context."""
    type: str  # ip, domain, url_pattern, payload, user_agent
    value: str
    original_severity: str
    original_context: str
    dns_records: list[DNSRecord] = field(default_factory=list)
    geo: GeoInfo | None = None
    reputation: ReputationScore | None = None
    related_iocs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class ThreatReport:
    """The full enriched threat intelligence report."""
    generated_at: str
    total_iocs: int = 0
    enriched_count: int = 0
    iocs: list[EnrichedIOC] = field(default_factory=list)
    attack_summary: dict[str, Any] = field(default_factory=dict)
    mitre_mappings: list[dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# IP classification (RFC-based, no external queries)
# ---------------------------------------------------------------------------

BOGON_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
]

BOGON_NETS = [ipaddress.ip_network(r) for r in BOGON_RANGES]

REGISTRY_MAP = {
    "2.0.0.0/8": "RIPE", "5.0.0.0/8": "RIPE",
    "31.0.0.0/8": "RIPE", "37.0.0.0/8": "RIPE",
    "46.0.0.0/8": "RIPE", "62.0.0.0/8": "RIPE",
    "77.0.0.0/8": "RIPE", "78.0.0.0/8": "RIPE",
    "80.0.0.0/8": "RIPE", "81.0.0.0/8": "RIPE",
    "3.0.0.0/8": "ARIN", "4.0.0.0/8": "ARIN",
    "8.0.0.0/8": "ARIN", "12.0.0.0/8": "ARIN",
    "13.0.0.0/8": "ARIN", "15.0.0.0/8": "ARIN",
    "23.0.0.0/8": "ARIN", "24.0.0.0/8": "ARIN",
    "34.0.0.0/8": "ARIN", "35.0.0.0/8": "ARIN",
    "1.0.0.0/8": "APNIC", "14.0.0.0/8": "APNIC",
    "27.0.0.0/8": "APNIC", "36.0.0.0/8": "APNIC",
    "39.0.0.0/8": "APNIC", "42.0.0.0/8": "APNIC",
    "43.0.0.0/8": "APNIC", "49.0.0.0/8": "APNIC",
    "41.0.0.0/8": "AFRINIC", "102.0.0.0/8": "AFRINIC",
    "105.0.0.0/8": "AFRINIC", "154.0.0.0/8": "AFRINIC",
    "177.0.0.0/8": "LACNIC", "179.0.0.0/8": "LACNIC",
    "181.0.0.0/8": "LACNIC", "186.0.0.0/8": "LACNIC",
    "187.0.0.0/8": "LACNIC", "189.0.0.0/8": "LACNIC",
    "190.0.0.0/8": "LACNIC", "191.0.0.0/8": "LACNIC",
    "200.0.0.0/8": "LACNIC", "201.0.0.0/8": "LACNIC",
}


def is_bogon(ip_str: str) -> bool:
    """Check whether an IP falls in a bogon/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in BOGON_NETS)


def is_private(ip_str: str) -> bool:
    """Check whether an IP is in a private range."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def guess_registry(ip_str: str) -> str:
    """Guess the regional internet registry from the IP's first octet."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"
    for prefix, registry in REGISTRY_MAP.items():
        if addr in ipaddress.ip_network(prefix):
            return registry
    return "unknown"


# ---------------------------------------------------------------------------
# DNS enrichment (reverse DNS only — no external API needed)
# ---------------------------------------------------------------------------

def reverse_dns(ip_str: str) -> str | None:
    """Attempt reverse DNS lookup. Returns hostname or None."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def enrich_ip_dns(ip_str: str) -> list[DNSRecord]:
    """Get DNS records for an IP address."""
    records: list[DNSRecord] = []
    rdns = reverse_dns(ip_str)
    if rdns:
        records.append(DNSRecord(
            hostname=rdns,
            record_type="PTR",
            value=ip_str,
        ))
    return records


# ---------------------------------------------------------------------------
# Reputation scoring (heuristic, based on observable patterns)
# ---------------------------------------------------------------------------

SCANNER_UA_FRAGMENTS = [
    "nikto", "nmap", "sqlmap", "wpscan", "dirbuster", "gobuster",
    "nuclei", "burp", "zap", "acunetix", "nessus", "masscan",
    "hydra", "medusa", "patator",
]

SQLI_INDICATORS = [
    "union select", "or 1=1", "sleep(", "benchmark(",
    "information_schema", "load_file(",
]

XSS_INDICATORS = ["<script", "javascript:", "onerror=", "onload="]

BRUTE_INDICATORS = ["failed login", "brute-force", "brute force"]


def score_ioc(ioc_type: str, value: str, context: str) -> ReputationScore:
    """Assign a reputation score based on IOC type and context."""
    reasons: list[str] = []
    score = 0
    category = "unknown"

    ctx_lower = context.lower()

    if ioc_type == "ip":
        if is_bogon(value):
            reasons.append("Bogon/reserved IP range — should never appear in external traffic")
            score += 30
        if is_private(value):
            reasons.append("Private IP — internal network address appearing in external context")
            score += 20

    if ioc_type == "user_agent":
        val_lower = value.lower()
        for frag in SCANNER_UA_FRAGMENTS:
            if frag in val_lower:
                reasons.append(f"Known scanner tool: {frag}")
                score += 40
                category = "scanner"
                break

    if ioc_type == "payload":
        val_lower = value.lower()
        for ind in SQLI_INDICATORS:
            if ind in val_lower:
                reasons.append(f"SQL injection pattern: {ind}")
                score += 50
                category = "injector"
                break
        for ind in XSS_INDICATORS:
            if ind in val_lower:
                reasons.append(f"XSS pattern: {ind}")
                score += 40
                category = "injector"
                break

    for ind in BRUTE_INDICATORS:
        if ind in ctx_lower:
            reasons.append("Brute-force behaviour detected")
            score += 50
            category = "bruteforcer"
            break

    if "sqli" in ctx_lower or "sql injection" in ctx_lower:
        if category == "unknown":
            category = "injector"
        score += 20
        reasons.append("Associated with SQL injection activity")

    if "scanner" in ctx_lower or "nikto" in ctx_lower:
        if category == "unknown":
            category = "scanner"
        score += 15
        reasons.append("Associated with automated scanning")

    if "critical" in ctx_lower:
        score += 10

    score = min(score, 100)

    if score >= 70:
        confidence = "high"
    elif score >= 40:
        confidence = "medium"
    else:
        confidence = "low"

    if not reasons:
        reasons.append("No specific malicious indicators — review manually")

    return ReputationScore(
        score=score,
        category=category,
        confidence=confidence,
        reasons=reasons,
    )


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------

MITRE_MAP = {
    "scanner": [
        {"tactic": "Reconnaissance", "technique": "T1595",
         "name": "Active Scanning"},
        {"tactic": "Discovery", "technique": "T1046",
         "name": "Network Service Discovery"},
    ],
    "bruteforcer": [
        {"tactic": "Credential Access", "technique": "T1110",
         "name": "Brute Force"},
        {"tactic": "Initial Access", "technique": "T1078",
         "name": "Valid Accounts"},
    ],
    "injector": [
        {"tactic": "Initial Access", "technique": "T1190",
         "name": "Exploit Public-Facing Application"},
        {"tactic": "Execution", "technique": "T1059",
         "name": "Command and Scripting Interpreter"},
    ],
}


def map_to_mitre(categories: set[str]) -> list[dict[str, str]]:
    """Map IOC categories to MITRE ATT&CK techniques."""
    seen = set()
    mappings: list[dict[str, str]] = []
    for cat in categories:
        for entry in MITRE_MAP.get(cat, []):
            key = entry["technique"]
            if key not in seen:
                seen.add(key)
                mappings.append(entry)
    return mappings


# ---------------------------------------------------------------------------
# Enrichment pipeline
# ---------------------------------------------------------------------------

def enrich_ioc(raw: dict, resolve_dns: bool = False) -> EnrichedIOC:
    """Enrich a single IOC with all available intelligence."""
    ioc_type = raw.get("type", "unknown")
    value = raw.get("value", "")
    severity = raw.get("severity", "medium")
    context = raw.get("context", "")

    enriched = EnrichedIOC(
        type=ioc_type,
        value=value,
        original_severity=severity,
        original_context=context,
    )

    if ioc_type == "ip":
        if is_private(value):
            enriched.tags.append("internal")
        if is_bogon(value):
            enriched.tags.append("bogon")

        registry = guess_registry(value)
        enriched.geo = GeoInfo(registry=registry)

        if resolve_dns:
            enriched.dns_records = enrich_ip_dns(value)

    if ioc_type == "user_agent":
        enriched.tags.append("tool-signature")

    if ioc_type == "payload":
        val_lower = value.lower()
        if any(i in val_lower for i in SQLI_INDICATORS):
            enriched.tags.append("sqli")
        if any(i in val_lower for i in XSS_INDICATORS):
            enriched.tags.append("xss")

    enriched.reputation = score_ioc(ioc_type, value, context)

    return enriched


def enrich_all(iocs: list[dict], resolve_dns: bool = False) -> ThreatReport:
    """Enrich all IOCs and build the full threat report."""
    enriched: list[EnrichedIOC] = []
    categories: set[str] = set()
    severity_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)

    for raw in iocs:
        e = enrich_ioc(raw, resolve_dns=resolve_dns)
        enriched.append(e)
        severity_counts[e.original_severity] += 1
        type_counts[e.type] += 1
        if e.reputation:
            categories.add(e.reputation.category)

    ip_iocs = [e for e in enriched if e.type == "ip"]
    for e in enriched:
        if e.type != "ip":
            for ip_e in ip_iocs:
                if ip_e.value in e.original_context:
                    e.related_iocs.append(ip_e.value)

    mitre = map_to_mitre(categories)

    high_risk = [e for e in enriched if e.reputation and e.reputation.score >= 50]

    return ThreatReport(
        generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        total_iocs=len(iocs),
        enriched_count=len(enriched),
        iocs=enriched,
        attack_summary={
            "severity_breakdown": dict(severity_counts),
            "ioc_types": dict(type_counts),
            "threat_categories": sorted(categories),
            "high_risk_count": len(high_risk),
        },
        mitre_mappings=mitre,
    )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def to_markdown(report: ThreatReport) -> str:
    """Render the threat report as markdown."""
    lines = ["# Threat intelligence report", ""]
    lines.append(f"Generated: {report.generated_at}")
    lines.append(f"IOCs analysed: {report.total_iocs}")
    lines.append("")

    s = report.attack_summary
    lines.append("## Attack profile")
    lines.append("")
    cats = s.get("threat_categories", [])
    if cats:
        lines.append(f"**Threat categories:** {', '.join(cats)}")
    lines.append(f"**High-risk IOCs:** {s.get('high_risk_count', 0)}")
    lines.append("")

    sev = s.get("severity_breakdown", {})
    if sev:
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for k in ["critical", "high", "medium", "low"]:
            if k in sev:
                lines.append(f"| {k.title()} | {sev[k]} |")
        lines.append("")

    if report.mitre_mappings:
        lines.append("## MITRE ATT&CK mapping")
        lines.append("")
        lines.append("| Tactic | Technique | Name |")
        lines.append("|---|---|---|")
        for m in report.mitre_mappings:
            lines.append(f"| {m['tactic']} | {m['technique']} | {m['name']} |")
        lines.append("")

    lines.append("## Enriched IOCs")
    lines.append("")
    for e in report.iocs:
        lines.append(f"### `{e.value}` ({e.type})")
        lines.append("")
        lines.append(f"- **Original severity:** {e.original_severity}")
        lines.append(f"- **Context:** {e.original_context}")

        if e.reputation:
            lines.append(f"- **Reputation score:** {e.reputation.score}/100 ({e.reputation.confidence} confidence)")
            lines.append(f"- **Category:** {e.reputation.category}")
            for r in e.reputation.reasons:
                lines.append(f"  - {r}")

        if e.tags:
            lines.append(f"- **Tags:** {', '.join(e.tags)}")

        if e.geo and e.geo.registry:
            lines.append(f"- **Registry:** {e.geo.registry}")

        if e.dns_records:
            for rec in e.dns_records:
                lines.append(f"- **{rec.record_type}:** {rec.hostname}")

        if e.related_iocs:
            lines.append(f"- **Related IPs:** {', '.join(e.related_iocs)}")

        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Threat intelligence enricher")
    parser.add_argument("input", nargs="?", help="IOCs JSON file (from project 8 or manual)")
    parser.add_argument("--ip", action="append", default=[],
                        help="Enrich a single IP (repeatable)")
    parser.add_argument("--resolve-dns", action="store_true",
                        help="Attempt reverse DNS lookups (requires network)")
    parser.add_argument("--out", default="enriched",
                        help="Output base name (writes .md and .json)")
    args = parser.parse_args()

    iocs: list[dict] = []

    if args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: {input_path} not found", file=sys.stderr)
            sys.exit(1)
        data = json.loads(input_path.read_text())
        if isinstance(data, list):
            iocs = data
        elif isinstance(data, dict):
            iocs = data.get("iocs", [])

    for ip in args.ip:
        iocs.append({"type": "ip", "value": ip, "severity": "unknown", "context": "manual input"})

    if not iocs:
        print("No IOCs provided. Use a JSON file or --ip flags.", file=sys.stderr)
        sys.exit(1)

    report = enrich_all(iocs, resolve_dns=args.resolve_dns)

    md_path = Path(f"{args.out}.md")
    md_path.write_text(to_markdown(report))

    json_path = Path(f"{args.out}.json")
    json_data = {
        "generated_at": report.generated_at,
        "total_iocs": report.total_iocs,
        "enriched_count": report.enriched_count,
        "attack_summary": report.attack_summary,
        "mitre_mappings": report.mitre_mappings,
        "iocs": [asdict(e) for e in report.iocs],
    }
    json_path.write_text(json.dumps(json_data, indent=2))

    print(f"Report written to {md_path} and {json_path}")
    print(f"  IOCs enriched: {report.enriched_count}")
    high_risk = report.attack_summary.get("high_risk_count", 0)
    print(f"  High-risk IOCs: {high_risk}")
    print(f"  MITRE techniques: {len(report.mitre_mappings)}")


if __name__ == "__main__":
    main()
