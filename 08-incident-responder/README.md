# Project 8: Incident response toolkit

Takes alerts from project 6's log analyser (or raw log files directly) and generates a complete incident response package: IOC extraction, firewall block rules, YARA detection rules, a chronological timeline, and prioritised recommendations.

Completes the purple-team cycle: **attack** (project 3) → **detect** (project 6) → **respond** (project 8).

```bash
cd 08-incident-responder

# From pre-existing alerts JSON:
python responder.py alerts.json --out response-package

# From raw access logs (runs detection internally):
python responder.py access.log --parse-first --out response-package
```

## What it generates

| Artifact | Format | Purpose |
|---|---|---|
| IOC list | Table in report, JSON array | Feed into threat intel platform or share with other teams |
| Firewall rules | iptables commands | Block attacker IPs immediately |
| YARA rules | `.yar` syntax | Detect the same attack patterns in other log sources or network captures |
| Timeline | Chronological table | Reconstruct the attack sequence for the incident report |
| Recommendations | Prioritised list | Actionable steps: what to patch, what to block, what to investigate |

## How it builds on the portfolio

| Connection | What it reuses |
|---|---|
| Project 6 (log analyser) | Consumes alert output directly; can also parse raw logs with the same detection patterns |
| Project 3 (vuln scanner) | The scanner generates the attack traffic that project 6 detects and project 8 responds to |
| Project 1 (headers auditor) | Recommendations reference the same security headers (CSP, HSTS) that project 1 checks |

## Response workflow

1. **Ingest** — reads alerts JSON (from project 6) or parses raw Apache/nginx logs
2. **Extract IOCs** — identifies attacker IPs, malicious user-agents, and attack payloads
3. **Generate firewall rules** — creates iptables DROP rules for critical/high-severity source IPs
4. **Build YARA rules** — converts observed SQLi, XSS, and traversal payloads into detection signatures
5. **Construct timeline** — orders all events chronologically for the incident narrative
6. **Recommend** — generates prioritised remediation steps based on which attack types were detected

## Safety

This tool reads and processes data. It generates firewall rules and YARA rules as text files for human review — it never executes them automatically. Always review generated rules before applying them to production systems.

## What I learned

- Incident response is a chain: detect, contain, eradicate, recover. This tool covers the first two. Containment (blocking IPs) happens within minutes; eradication (patching the vulnerability) takes longer.
- YARA rules are surprisingly simple to write but powerful in practice. The same rule that matches a log file can match a network capture or a memory dump.
- Automated response has limits. A firewall rule blocks an IP, but the attacker can rotate IPs. The real fix is patching the vulnerability they exploited.
- The IOC list is the bridge between teams. The SOC analyst extracts IOCs, the threat intel team enriches them, and the infrastructure team blocks them. Standardised formats (STIX/TAXII in production, plain JSON here) make that handoff possible.
